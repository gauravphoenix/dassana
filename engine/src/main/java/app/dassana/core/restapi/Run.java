package app.dassana.core.restapi;

import static app.dassana.core.contentmanager.ContentManager.GENERAL_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.NORMALIZE;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.RESOURCE_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.WORKFLOW_ID;
import static app.dassana.core.contentmanager.Parser.MISSING_NORMALIZATION_MSG;
import static app.dassana.core.workflow.processor.Decorator.DASSANA_KEY;

import app.dassana.core.contentmanager.ContentManager;
import app.dassana.core.contentmanager.Parser;
import app.dassana.core.launch.model.Message;
import app.dassana.core.launch.model.ProcessingResponse;
import app.dassana.core.launch.model.Request;
import app.dassana.core.launch.model.RunMode;
import app.dassana.core.launch.model.Severity;
import app.dassana.core.launch.model.WorkflowNotFoundException;
import app.dassana.core.normalize.model.NormalizerWorkflow;
import app.dassana.core.policycontext.model.PolicyContext;
import app.dassana.core.resource.model.GeneralContext;
import app.dassana.core.resource.model.ResourceContext;
import app.dassana.core.util.JsonyThings;
import app.dassana.core.util.StringyThings;
import app.dassana.core.workflow.WorkflowRunner;
import app.dassana.core.workflow.model.Workflow;
import app.dassana.core.workflow.model.WorkflowOutputWithRisk;
import app.dassana.core.workflow.processor.RequestProcessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.Gson;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.QueryValue;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.inject.Inject;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller("/run")
public class Run {


  @Inject private Gson gson;
  @Inject private RequestProcessor requestProcessor;
  @Inject private ContentManager contentManager;
  @Inject private Parser parser;
  @Inject private WorkflowRunner workflowRunner;


  private static final Logger logger = LoggerFactory.getLogger(Run.class);


  @Post
  public HttpResponse<String> processAlert(@Body Object input, @Nullable @QueryValue("workflowId") String workFlowId,
      @Nullable @QueryValue("includeInputRequest") Boolean includeInputRequest,
      @Nullable @QueryValue("mode") RunMode mode,
      @Nullable @Header("x-dassana-cache") Boolean useCache) throws Exception {

    try {
      //micronaut marshals the requests differently when invoked via AWS API Gateway
      String inputBody;
      if (input.getClass() == LinkedHashMap.class) {
        inputBody = gson.toJson(input);
        //in case we receive json array, we try to take the first element out of the array and assume it to be an
        // alert. (this is the case with GuardDuty raw findings (as opposed to GuardDuty findings sent to SecurityHub)
      } else if (input.getClass().getName().contentEquals("java.util.ArrayList")) {
        String arrayJson = gson.toJson(input);
        JSONArray jsonArray = new JSONArray(arrayJson);
        JSONObject jsonObject = jsonArray.getJSONObject(0);
        inputBody = jsonObject.toString();
      } else {
        inputBody = input.toString();
      }

      Request request = new Request(inputBody);
      request.setRunMode(Objects.requireNonNullElse(mode, RunMode.TEST));
      request.setUseCache(useCache == null || useCache);

      if (includeInputRequest == null) {
        includeInputRequest = false;
      }
      request.setIncludeOriginalAlert(includeInputRequest);

      if (StringUtils.isNotEmpty(inputBody)) {
        JSONObject inputJsonObj = new JSONObject(inputBody);
        JSONArray workflows = inputJsonObj.optJSONArray("workflows");
        if (workflows != null && workflows.length() > 0) {
          List<String> workflowStr = new LinkedList<>();
          for (int i = 0; i < workflows.length(); i++) {
            workflowStr.add(workflows.getString(i));
          }
          request.setAdditionalWorkflowYamls(workflowStr);
        }

      }

      JsonyThings.throwExceptionIfNotValidJsonObj(inputBody);

      if (StringUtils.isNotEmpty(workFlowId)) {
        request.setWorkflowId(workFlowId);
        requestProcessor.setWorkflows(request);

        Optional<Workflow> first = request.getWorkflowSetToRun().stream().findFirst();

        if (first.isPresent()) {
          Workflow workflow = first.get();
          Optional<WorkflowOutputWithRisk> workflowOutputWithRisk = Optional.empty();
          //todo: generify this
          if (workflow.getClass().getName().contentEquals(NormalizerWorkflow.class.getName())) {
            workflowOutputWithRisk = workflowRunner
                .runWorkFlow(NormalizerWorkflow.class, request, request.getInputJson());
          } else if (workflow.getClass().getName().contentEquals(GeneralContext.class.getName())) {
            workflowOutputWithRisk = workflowRunner.runWorkFlow(GeneralContext.class, request,
                request.getInputJson());
          } else if (workflow.getClass().getName().contentEquals(ResourceContext.class.getName())) {
            workflowOutputWithRisk = workflowRunner.runWorkFlow(ResourceContext.class, request,
                request.getInputJson());
          } else if (workflow.getClass().getName().contentEquals(PolicyContext.class.getName())) {
            workflowOutputWithRisk = workflowRunner.runWorkFlow(PolicyContext.class, request,
                request.getInputJson());
          }

          if (workflowOutputWithRisk.isPresent()) {
            WorkflowOutputWithRisk outputWithRisk = workflowOutputWithRisk.get();
            outputWithRisk.setStepOutput(outputWithRisk.getStepOutput());
            outputWithRisk.setWorkflowId(outputWithRisk.getWorkflowId());
            return HttpResponse.ok().body(gson.toJson(outputWithRisk));
          } else {//this shouldn't happen but still to be safe..
            return HttpResponse.ok().body("{}");
          }


        } else {
          throw new WorkflowNotFoundException(String.format("Sorry, we couldn't locate %s workflow", workFlowId));
        }


      }

      ProcessingResponse processingResponse = requestProcessor.processRequest(request);
      String decoratedJson = processingResponse.getDecoratedJson();
      return HttpResponse.ok().body(handleHints(decoratedJson, request));
    } catch (Exception e) {
      StringWriter sw = new StringWriter();
      PrintWriter pw = new PrintWriter(sw);
      e.printStackTrace(pw);
      return HttpResponse.badRequest().body(sw.toString());
    }


  }


  private String handleHints(String json, Request request) throws JsonProcessingException {

    JSONObject jsonObject = new JSONObject(json);
    JSONObject dassana = jsonObject.optJSONObject(DASSANA_KEY);

    if (dassana == null || !dassana.has(NORMALIZE)) {
      Message message = new Message();
      message.setSeverity(Severity.WARN);
      message.setMsg(MISSING_NORMALIZATION_MSG);
      jsonObject.put(DASSANA_KEY, new JSONObject(gson.toJson(message)));
    } else {//this means that normalization did occur

      String[] workflowKeys = {GENERAL_CONTEXT, RESOURCE_CONTEXT, POLICY_CONTEXT};

      for (String workflowKey : workflowKeys) {
        JSONObject workflowResponse = dassana.optJSONObject(workflowKey);
        if (workflowResponse == null) {
          Message message = new Message();
          message.setSeverity(Severity.INFO);
          message.setMsg(String.format("Sorry, but no %s workflow ran for the given alert. Please check filter config",
              workflowKey));
          jsonObject.getJSONObject(DASSANA_KEY).put(workflowKey, new JSONObject(gson.toJson(message)));
        } else {
          //check if the expected workflow did run or not
          if (request.getAdditionalWorkflowYamls() != null && request.getAdditionalWorkflowYamls().size() > 0) {

            for (String workflowYamlStr : request.getAdditionalWorkflowYamls()) {
              String workflowJson = StringyThings.getJsonFromYaml(workflowYamlStr);
              Workflow workflow = parser.getWorkflow(new JSONObject(workflowJson));
              String workflowType = workflowResponse.getString("workflowType");
              if (workflowType.contentEquals(workflow.getType())) {
                if (!workflow.getId().contentEquals(workflowResponse.getString(WORKFLOW_ID))) {
                  jsonObject.getJSONObject(DASSANA_KEY).put(workflowKey,
                      new JSONObject(gson.toJson(String.format("the output is from workflow id %s which doesn't "
                              + "match the workflowId provided, please check your filter config",
                          workflowResponse.getString(WORKFLOW_ID)))));
                }
              }


            }

          }

        }
      }


    }

    if (request.isIncludeOriginalAlert()) {
      return jsonObject.toString();
    } else {
      //we send the response like this (omitting the alert key)-

      /*{
        "dassana":{}
      }*/

      JSONObject dassanaObj = jsonObject.getJSONObject(DASSANA_KEY);
      JSONObject jsonObjectToReturn = new JSONObject();
      jsonObjectToReturn.put(DASSANA_KEY, dassanaObj);
      return jsonObjectToReturn.toString();
    }


  }

}
