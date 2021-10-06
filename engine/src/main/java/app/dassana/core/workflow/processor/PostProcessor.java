package app.dassana.core.workflow.processor;

import static app.dassana.core.contentmanager.ContentManager.NORMALIZE;
import static app.dassana.core.workflow.processor.Decorator.DASSANA_KEY;

import app.dassana.core.contentmanager.ContentManagerApi;
import app.dassana.core.launch.model.Request;
import app.dassana.core.normalize.model.NormalizerWorkflow;
import app.dassana.core.workflow.StepRunnerApi;
import app.dassana.core.workflow.model.Step;
import app.dassana.core.workflow.model.WorkflowOutputWithRisk;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class PostProcessor {

  @Inject ContentManagerApi contentManagerApi;

  @Inject private StepRunnerApi stepRunnerApi;

  private static final Logger logger = LoggerFactory.getLogger(PostProcessor.class);


  public String handlePostProcessor(Request request,
      WorkflowOutputWithRisk normalizationResult,
      String processedAlertWithS3key) throws Exception {

    NormalizerWorkflow normalizerWorkflow = (NormalizerWorkflow) request.getWorkflowIdToWorkflowMap()
        .get(normalizationResult.getWorkflowId());

    String normalizedJsonStr = new JSONObject(normalizationResult.getOutput()).toString();

    //we now run post processors of the normalization workflow, if any.
    Map<String, Object> stepIdToResponse = new HashMap<>();

    List<Step> postProcessorSteps = normalizerWorkflow.getPostProcessorSteps();
    for (Step step : postProcessorSteps) {
      String stepOutput = stepRunnerApi
          .runStep(normalizerWorkflow,
              step,
              processedAlertWithS3key,
              normalizedJsonStr)
          .getResponse();
      //we expect the post processor to provide either a json obj or an array, failing which we simply consider
      // it as a string
      try {
        stepIdToResponse.put(step.getId(), new JSONObject(stepOutput));
      } catch (JSONException e) {
        try {
          stepIdToResponse.put(step.getId(), new JSONArray(stepOutput));
        } catch (JSONException jsonException) {
          stepIdToResponse.put(step.getId(), stepOutput);
        }
      }
      logger.info("Post processor {} response :{}", step.getId(), stepOutput);
    }
    JSONObject finalJsonObj = new JSONObject(processedAlertWithS3key);
    JSONObject normalizeJsonObj = finalJsonObj.getJSONObject(DASSANA_KEY).getJSONObject(NORMALIZE);
    normalizeJsonObj.put("post-processor", stepIdToResponse);

    JSONObject dassana = finalJsonObj.getJSONObject(DASSANA_KEY);
    dassana.put("normalize", normalizeJsonObj);
    return finalJsonObj.toString();


  }


}
