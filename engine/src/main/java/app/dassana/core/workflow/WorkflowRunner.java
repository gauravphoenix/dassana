package app.dassana.core.workflow;

import app.dassana.core.launch.model.Message;
import app.dassana.core.launch.model.Request;
import app.dassana.core.launch.model.Severity;
import app.dassana.core.normalize.model.NormalizerWorkflow;
import app.dassana.core.resource.model.GeneralContext;
import app.dassana.core.risk.eval.RiskEvalException;
import app.dassana.core.risk.eval.RiskEvalRequest;
import app.dassana.core.risk.eval.RiskEvaluator;
import app.dassana.core.risk.model.Risk;
import app.dassana.core.risk.model.RiskConfig;
import app.dassana.core.util.JsonyThings;
import app.dassana.core.workflow.model.Component;
import app.dassana.core.workflow.model.Error;
import app.dassana.core.workflow.model.Output;
import app.dassana.core.workflow.model.Step;
import app.dassana.core.workflow.model.ValueType;
import app.dassana.core.workflow.model.Workflow;
import app.dassana.core.workflow.model.WorkflowOutput;
import app.dassana.core.workflow.model.WorkflowOutputException;
import app.dassana.core.workflow.model.WorkflowOutputWithRisk;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.google.gson.Gson;
import io.micronaut.core.util.StringUtils;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Singleton;
import net.thisptr.jackson.jq.BuiltinFunctionLoader;
import net.thisptr.jackson.jq.JsonQuery;
import net.thisptr.jackson.jq.Scope;
import net.thisptr.jackson.jq.Version;
import net.thisptr.jackson.jq.Versions;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class WorkflowRunner {

  private static final Logger logger = LoggerFactory.getLogger(WorkflowRunner.class);

  @Inject StepRunnerApi stepRunnerApi;
  @Inject private FilterMatch filterMatch;
  @Inject private RiskEvaluator riskEvaluator;

  Gson gson = new Gson();

  Scope rootScope = Scope.newEmptyScope();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public WorkflowRunner() {
    BuiltinFunctionLoader.getInstance().loadFunctions(Versions.JQ_1_6, rootScope);
  }

  public Optional<WorkflowOutputWithRisk> runWorkFlow(Class<? extends Workflow> workflowType,
      Request request,
      String simpleOutputJson) throws Exception {

    String jsonToUse;
    if (workflowType.getName().contentEquals(NormalizerWorkflow.class.getName())) {
      jsonToUse = request.getInputJson();
    } else {
      jsonToUse = simpleOutputJson;
    }

    WorkflowOutputWithRisk workflowOutputWithRisk = new WorkflowOutputWithRisk();
    List<Error> errorList = new LinkedList<>();
    workflowOutputWithRisk.setErrorList(errorList);

    Map<String, Object> stepToOutPutMap = new HashMap<>();
    JSONObject jsonObject;
    JsonyThings.throwExceptionIfNotValidJsonObj(jsonToUse);
    jsonObject = new JSONObject(jsonToUse);

    //let's find out applicable workflows
    Set<Workflow> candidates = new HashSet<>();
    for (Workflow workflow1 : request.getWorkflowSetToRun()) {
      if (workflow1.getClass() == workflowType) {
        candidates.add(workflow1);
      }
    }
    //.and match input against them
    Optional<Workflow> matchingWorkflow;

    //if a workflow has been provided with the request, no need to match anything
    if (StringUtils.isNotEmpty(request.getWorkflowId())) {
      Workflow workflow = request.getWorkflowIdToWorkflowMap().get(request.getWorkflowId());
      matchingWorkflow = Optional.of(workflow);

    } else {
      matchingWorkflow = filterMatch.getMatchingWorkflow(candidates, jsonToUse);
    }

    if (matchingWorkflow.isPresent()) {
      workflowOutputWithRisk.setWorkflowId(matchingWorkflow.get().getId());
      Workflow workflow = matchingWorkflow.get();
      List<Step> workflowSteps = workflow.getSteps();
      for (Step step : workflowSteps) {
        String stepPayload;
        if (!step.getFields().isEmpty()) {//the step uses "with" keyword
          stepPayload = getPayloadForStep(step.getFields(), stepToOutPutMap, jsonToUse);
        } else {
          stepPayload = jsonToUse;
        }
        String stepOutputJson;
        try {
          stepOutputJson = runStep(workflow, step, stepPayload, simpleOutputJson);
          Object fromJson = gson.fromJson(stepOutputJson, Object.class);
          logger.info("Output from step {} in workflow {} is {}", step.getId(), workflow.getId(), stepOutputJson);
          stepToOutPutMap.put(step.getId(), fromJson);

          //merge the step results into the event
          for (Entry<String, Object> mapEntry : stepToOutPutMap.entrySet()) {
            String stepId = mapEntry.getKey();
            Object stepOutput = mapEntry.getValue();
            jsonObject.put(stepId, stepOutput);
          }

          List<Map<String, Object>> list = new LinkedList<>();

          for (Entry<String, Object> entry : stepToOutPutMap.entrySet()) {
            String stepId = entry.getKey();
            Object o = entry.getValue();

            Map<String, Object> map = new HashMap<>();
            map.put(stepId, o);
            list.add(map);

          }
          workflowOutputWithRisk.setStepOutput(list);
        } catch (Exception e) {
          Error error = new Error(workflow.getId(), workflow.getType(), Component.STEP, step.getId(),
              new Message(e.getMessage(),
                  Severity.ERROR));
          errorList.add(error);

        }

      }

      String workflowOutput;
      try {
        workflowOutput = getWorkflowOutput(workflow.getOutput(), jsonObject.toString());
        workflowOutputWithRisk.setOutput(getSimpleOutput(workflowOutput, workflow));
      } catch (WorkflowOutputException e) {
        Error error = new Error(workflow.getId(), workflow.getType(), Component.WORKFLOW_OUTPUT, e.getOutputField(),
            new Message(e.getMessage(), Severity.ERROR));
        errorList.add(error);
      }

      //handle risk
      if (workflow instanceof GeneralContext) {
        RiskConfig riskConfig;
        var resPriWorkflow = (GeneralContext) workflow;
        riskConfig = resPriWorkflow.getRiskConfig();
        try {
          workflowOutputWithRisk
              .setRisk(getRisk(riskConfig, workflowOutputWithRisk, simpleOutputJson));
        } catch (RiskEvalException e) {
          Error error = new Error(workflow.getId(), workflow.getType(), Component.RISK_CALC, e.getRuleName(),
              new Message(e.getMessage(), Severity.ERROR));
          errorList.add(error);

        }
      }

      return Optional.of(workflowOutputWithRisk);


    }

    return Optional.empty();
  }


  private String getWorkflowOutput(List<Output> output, String jsonStr) {

    JSONObject jsonObject = new JSONObject();

    for (Output map : output) {
      String fieldName = map.getName();
      try {

        String value = map.getValue();

        if (map.getValueType().equals(ValueType.JQ_EXPRESSION)) {
          JsonQuery jsonQuery = JsonQuery.compile(value, Version.LATEST);
          JsonNode in = MAPPER.readTree(jsonStr);

          Scope childScope = Scope.newChildScope(rootScope);

          jsonQuery.apply(childScope, in, jsonNode -> {
            Object o = gson.fromJson(jsonNode.toString(), Object.class);
            jsonObject.put(fieldName, o);
          });

        } else if (map.getValueType().equals(ValueType.STRING)) {
          jsonObject.put(map.getName(), map.getValue());
        }
      } catch (Exception e) {
        WorkflowOutputException workflowOutputException = new WorkflowOutputException();
        workflowOutputException.setOutputField(fieldName);
        throw workflowOutputException;
      }

    }

    return jsonObject.toString();
  }


  /**
   * simpleoutput refers to the output of the workflow. It converts the YAML array that you define at the bottom of the
   * workflows to a JSON object
   */
  private Map<String, Object> getSimpleOutput(String workflowOutPutJsonStr, Workflow workflow) {

    JSONObject workflowOutPutJsonObj = new JSONObject(workflowOutPutJsonStr);
    Map<String, Object> stringObjectMap = workflowOutPutJsonObj.toMap();

    Map<String, Object> simpleOutput = new HashMap<>();
    for (Output output : workflow.getOutput()) {

      for (Entry<String, Object> entry : stringObjectMap.entrySet()) {
        String s = entry.getKey();
        Object o = entry.getValue();

        if (output.getName().contentEquals(s)) {
          simpleOutput.put(s, o);
        }

      }

    }
    return simpleOutput;

  }

  private Risk getRisk(RiskConfig riskConfig, WorkflowOutput workflowOutput,
      String simpleOutputJson) {
    JSONObject requestJsonObjForRiskCalc = new JSONObject();

    //the normalized fields should be available for risk rules in addition to the fields returned by steps
    Map<String, Object> normalizedJsonMap = new JSONObject(simpleOutputJson).toMap();
    normalizedJsonMap.forEach(requestJsonObjForRiskCalc::put);

    for (Map<String, Object> map : workflowOutput.getStepOutput()) {
      for (String key : map.keySet()) {
        requestJsonObjForRiskCalc.put(key, map.get(key));
      }
    }

    RiskEvalRequest riskEvalRequest = new RiskEvalRequest();
    riskEvalRequest.setJsonData(requestJsonObjForRiskCalc.toString());
    riskEvalRequest.setRiskRules(riskConfig.getRiskRules());
    riskEvalRequest.setDefaultRisk(riskConfig.getDefaultRisk());
    return riskEvaluator.evaluate(riskEvalRequest);
  }

  private String getPayloadForStep(List<Map<String, String>> fields,
      Map<String, Object> stepToOutPutMap,
      String inputJson) throws JsonProcessingException {

    JSONObject eventPayloadJsonObject = new JSONObject(inputJson);

    Map<String, Object> eventPayloadAsMap = eventPayloadJsonObject.toMap();
    eventPayloadAsMap.put("steps", stepToOutPutMap);

    JSONObject mergedJsonObj = new JSONObject(eventPayloadAsMap);

    JSONObject fieldJsonObj = new JSONObject();

    for (Map<String, String> field : fields) {

      String name = field.get("name");
      String value = field.get("value");
      String valueType = field.get("value-type");

      if (StringUtils.isEmpty(valueType) || valueType.contentEquals("jq")) { //assume the value type to be a
        // JQ value type

        JsonQuery jsonQuery = JsonQuery.compile(value, Version.LATEST);
        JsonNode in = MAPPER.readTree(mergedJsonObj.toString());

        Scope childScope = Scope.newChildScope(rootScope);
        jsonQuery.apply(childScope, in, out -> {

          if (out.getNodeType().equals(JsonNodeType.ARRAY)) {
            fieldJsonObj.put(name, new JSONArray(out.toString()));
          }

          if (out.getNodeType().equals(JsonNodeType.STRING)) {
            fieldJsonObj.put(name, out.asText());
          }
          if (out.getNodeType().equals(JsonNodeType.OBJECT)) {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> result = mapper.convertValue(out, new TypeReference<>() {
            });
            fieldJsonObj.put(name, result);
          }
          if (out.getNodeType().equals(JsonNodeType.NUMBER)) {
            fieldJsonObj.put(name, out.asLong());
          }
          if (out.getNodeType().equals(JsonNodeType.BOOLEAN)) {
            fieldJsonObj.put(name, out.asBoolean());
          }
        });

      } else if (valueType.contentEquals("STRING")) {
        fieldJsonObj.put(name, value);
      }

    }

    return fieldJsonObj.toString();

  }


  private String runStep(Workflow workflow, Step step, String payLoad, String workflowOutput) throws Exception {
    return stepRunnerApi.runStep(workflow, step, payLoad, workflowOutput).getResponse();

  }


}