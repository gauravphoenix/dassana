package app.dassana.core.workflow.infra;

import app.dassana.core.resource.model.GeneralContext;
import app.dassana.core.workflow.StepRunnerApi;
import app.dassana.core.workflow.model.Step;
import app.dassana.core.workflow.model.StepExecutionRuntimeException;
import app.dassana.core.workflow.model.StepRunResponse;
import app.dassana.core.workflow.model.Workflow;
import app.dassana.core.workflow.model.runtime.AwsRuntimeContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.cache.annotation.Cacheable;
import io.micronaut.core.util.StringUtils;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.cloudformation.model.ListStackResourcesRequest;
import software.amazon.awssdk.services.cloudformation.model.ListStackResourcesResponse;
import software.amazon.awssdk.services.cloudformation.model.StackResourceSummary;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.GetFunctionRequest;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;

@Singleton
public class LambdaStepRunner implements StepRunnerApi {

  private static final Logger logger = LoggerFactory.getLogger(LambdaStepRunner.class);
  @Inject LambdaClient lambdaClient;
  @Inject CloudFormationClient cfClient;
  @Inject RuntimeHelper runtimeHelper;


  public LambdaStepRunner() {
  }

  @Cacheable("function-names")
  public String getFunctionNameFromWorkFlow(String uses) {

    ListStackResourcesResponse listStackResourcesResponse = cfClient
        .listStackResources(ListStackResourcesRequest.builder().
            stackName(runtimeHelper.getStackName()).
            build());

    List<StackResourceSummary> stackResourceSummaries = listStackResourcesResponse
        .stackResourceSummaries();

    for (StackResourceSummary summary : stackResourceSummaries) {

      if (summary.logicalResourceId().contentEquals(uses)) {
        return summary.physicalResourceId();
      }
    }

    //perhaps, this function hasn't been updated yet, so let's call the lambda api to make sure it exists
    try {
      lambdaClient.getFunction(GetFunctionRequest.builder().functionName(uses).build())
          .code();
      return uses;
    } catch (Exception e) {
      throw new RuntimeException(String.format("Function %s not found", uses));
    }

  }


  @Override
  public StepRunResponse runStep(Workflow workflow, Step step, String payLoad,
      String simpleOutputJsonStr)
      throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    JsonNode jsonNode = mapper.readValue(payLoad, JsonNode.class);
    logger.info("Running step {} of workflow {} with payload {}", step.getId(), workflow.getId(), jsonNode.toString());

    StepRunResponse stepRunResponse = new StepRunResponse();

    RuntimeContext runtimeContext = getRuntimeContext(workflow, simpleOutputJsonStr);
    stepRunResponse.setRuntimeContext(runtimeContext);
    InvokeResponse invokeResponse = lambdaClient.invoke(InvokeRequest.builder().
        invocationType(InvocationType.REQUEST_RESPONSE).
        payload(SdkBytes.fromUtf8String(payLoad)).
        clientContext(runtimeContext.getContext()).
        functionName(getFunctionNameFromWorkFlow(step.getUses())).
        build());

    if (StringUtils.isNotEmpty(invokeResponse.functionError())) {
      throw new StepExecutionRuntimeException(
          String.format("Error in running step %s in workflow %s , input sent to the action was "
                  + "%s and  the response from action  is %s", step.getId(), workflow.getId(), payLoad,
              invokeResponse.payload().asString(Charset.defaultCharset())));

    } else {
      stepRunResponse.setResponse(invokeResponse.payload().asString(Charset.defaultCharset()));
      return stepRunResponse;
    }
  }


  public class RuntimeContext {

    private String context;
    private boolean crossAccountRoleUsed;
    private String crossAccountRoleName;

    public String getContext() {
      return context;
    }

    public void setContext(String context) {
      this.context = context;
    }

    public boolean isCrossAccountRoleUsed() {
      return crossAccountRoleUsed;
    }

    public void setCrossAccountRoleUsed(boolean crossAccountRoleUsed) {
      this.crossAccountRoleUsed = crossAccountRoleUsed;
    }

    public String getCrossAccountRoleName() {
      return crossAccountRoleName;
    }

    public void setCrossAccountRoleName(String crossAccountRoleName) {
      this.crossAccountRoleName = crossAccountRoleName;
    }
  }


  private RuntimeContext getRuntimeContext(Workflow workflow, String simpleOutputJsonStr) {

    if (simpleOutputJsonStr.contentEquals("{}")) {
      return new RuntimeContext();
    }

    String contextJson = "{}";

    RuntimeContext getRunTimeContextResponse = new RuntimeContext();

    if (workflow instanceof GeneralContext) {

      JSONObject jsonObject = new JSONObject(simpleOutputJsonStr);
      String resourceContainer = jsonObject.getString("resourceContainer");

      if (runtimeHelper.crossAccountRoleRequired(resourceContainer)) {

        AwsRuntimeContext awsRuntimeContext = runtimeHelper.getAwsRuntimeContext(resourceContainer,
            jsonObject.getString("region"));

        String accessKey = awsRuntimeContext.getAwsCreds().getAccessKey();
        String secretKey = awsRuntimeContext.getAwsCreds().getSecretKey();
        String sessionToken = awsRuntimeContext.getAwsCreds().getSessionToken();
        String resourceRegion = awsRuntimeContext.getResourceRegion();

        JSONObject custom = new JSONObject();
        custom.put("AWS_ACCESS_KEY_ID", accessKey);
        custom.put("AWS_SECRET_ACCESS_KEY", secretKey);
        custom.put("AWS_SESSION_TOKEN", sessionToken);
        custom.put("AWS_REGION", resourceRegion);

        JSONObject customObj = new JSONObject();
        customObj.put("custom", custom);
        contextJson = customObj.toString();
        getRunTimeContextResponse.setCrossAccountRoleUsed(true);
        getRunTimeContextResponse
            .setCrossAccountRoleName(System.getenv("dassanaCrossAccountRoleName"));

      }


    }

    getRunTimeContextResponse.setContext(
        Base64.getEncoder().encodeToString(contextJson.getBytes(StandardCharsets.UTF_8)));

    return getRunTimeContextResponse;


  }


}
