/*
package app.dassana.core.launch;


import static app.dassana.core.contentmanager.ContentManager.GENERAL_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.NORMALIZE;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.WORKFLOW_ID;
import static app.dassana.core.contentmanager.Parser.MISSING_NORMALIZATION_MSG;
import static app.dassana.core.util.JsonyThings.MESSAGE;
import static app.dassana.core.workflow.processor.Decorator.DASSANA_KEY;

import app.dassana.core.api.DassanaWorkflowValidationException;
import app.dassana.core.contentmanager.RemoteContentDownloadApi;
import app.dassana.core.contentmanager.infra.S3Downloader;
import app.dassana.core.launch.model.ProcessingResponse;
import app.dassana.core.workflow.StepRunnerApi;
import app.dassana.core.workflow.infra.LambdaStepRunner;
import app.dassana.core.workflow.model.Step;
import app.dassana.core.workflow.model.StepRunResponse;
import app.dassana.core.workflow.model.Workflow;
import app.dassana.core.workflow.model.WorkflowOutputWithRisk;
import app.dassana.core.workflow.processor.EventBridgeHandler;
import app.dassana.core.workflow.processor.S3Manager;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.commons.io.IOUtils;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.StringUtils;
import software.amazon.awssdk.services.s3.S3Client;

@MicronautTest
public class ApiSqsHandlerTest {


  @Test
  void testNormalizationException() throws IOException {

    String file = "inputs/validShAlertWithBadNormalizer.json";

    Map<String, String> queryParams = new HashMap<>();
    queryParams = helper.getQueryParams(false);
    String executeRunApi = helper.executeRunApi(helper.getFileContent(file), queryParams);
    Assertions.assertTrue(executeRunApi.contains(
        "Sorry but the normalizer aws-config-via-security-hub threw error csp is expected to be not empty"));


  }


  @Test
  void testIncludeJson() throws Exception {

    String file = "inputs/validSecurityHubAlert.json";

    Map<String, String> queryParams = helper.getQueryParams(true);
    queryParams = helper.getQueryParams(false);
    String response = helper.executeRunApi(helper.getFileContent(file), queryParams);
    JSONObject jsonObject = new JSONObject(response);
    if (jsonObject.has(DASSANA_KEY)) {
      Assertions.fail("did not expect to see Dassana Key");
    }

    file = "inputs/validJsonButNotAnAlert1.json";
    response = helper.executeRunApi(helper.getFileContent(file), queryParams);

    jsonObject = new JSONObject(response);
    String msg = jsonObject.getString("msg");

    if (!msg.contentEquals(MISSING_NORMALIZATION_MSG)) {
      Assertions.fail("Expected to see missing normalization message");
    }

  }

  @Test
  void testValidateApi() throws Exception {

    helper.executeValidateApi("validationRequests/validWorkflow.yaml");

    boolean exceptionThrown = false;
    try {
      helper.executeValidateApi("validationRequests/invalidWorkflowYaml.json");
    } catch (DassanaWorkflowValidationException exception) {
      exceptionThrown = true;
    }
    Assertions.assertTrue(exceptionThrown, "expected to see invalidWorkflowYaml.json fail the "
        + "validation test");
    exceptionThrown = false;
    try {
      helper.executeValidateApi("validationRequests/validWorkflowButWithInvalidRule.json");
    } catch (DassanaWorkflowValidationException exception) {
      exceptionThrown = true;
    }
    Assertions.assertTrue(exceptionThrown, "expected to see validWorkflowButWithInvalidRule fail the "
        + "validation test");
    exceptionThrown = false;
    try {
      helper.executeValidateApi("validationRequests/invalidWorkflowType.json");
    } catch (DassanaWorkflowValidationException e) {
      exceptionThrown = true;
    }
    Assertions.assertTrue(exceptionThrown, "expected to see invalidWorkflowType fail the "
        + "validation test");

  }

  @Test
  void testWorkflowGet() {
    Map<String, String> queryParams = helper.getQueryParams(false);
    queryParams.put(WORKFLOW_ID, "foo");
    APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent = helper.executeRunApiGet(queryParams);
    Assertions.assertEquals(404, (int) apiGatewayProxyResponseEvent.getStatusCode());
    queryParams.put(WORKFLOW_ID, "foo-cloud-normalize");
    Assertions.assertEquals(200, (int) helper.executeRunApiGet(queryParams).getStatusCode());
  }

  @Test
  void handleRunTestForASpecificWorkflow() throws IOException {
    Map<String, String> queryParams = helper.getQueryParams(false);
    queryParams.put(WORKFLOW_ID, "foo-cloud-normalize");
    String executeRunApiResponse = helper.executeRunApi(helper.getFileContent("inputs/validSecurityHubAlert.json"),
        queryParams);
    Assertions.assertTrue(executeRunApiResponse.contentEquals("{}"));

  }


  @Test
  void testDraftWorkflow() throws IOException {
    Map<String, String> queryParams = helper.getQueryParams(false);
    String response = helper
        .executeRunApi(helper.getFileContent("inputs/validAlertWithDraftWorkflow.json"), queryParams);
    JSONObject jsonObject = new JSONObject(response);
    Assertions.assertTrue(jsonObject.getString("msg").contentEquals(MISSING_NORMALIZATION_MSG));

  }


  @Test
  void ensureValidJsonIsAlwaysReturned() throws Exception {

    String[] fileNames = new String[]{"inputs/validJsonButNotAnAlert1.json", "inputs/validJsonButNotAnAlert2.json"};
    Map<String, String> queryParams = helper.getQueryParams(true);
    for (String fileName : fileNames) {
      String response = helper.executeRunApi(helper.getFileContent(fileName), queryParams);
      JSONObject jsonObject = new JSONObject(response);
      jsonObject.remove(DASSANA_KEY);//this key is always added
      JSONObject jsonObjectInput = new JSONObject(helper.getFileContent(fileName));
      Assertions.assertEquals(jsonObjectInput.toString(), jsonObject.toString());
    }


  }


  @Test()
  void ensureInValidJsonThrowsError() {
    String foo = helper.executeRunApi("foo", new HashMap<>());
    Assertions.assertTrue(foo.contains(MESSAGE));

  }


  @Test
  void ensureValidAlertGetsProcessed() throws IOException {
    Map<String, String> queryParams = helper.getQueryParams(true);

    String response = helper.executeRunApi(helper.getFileContent("inputs/validSecurityHubAlert.json"),
        queryParams);
    JSONObject responseJsonObj = new JSONObject(response);
    JSONObject dassana = responseJsonObj.getJSONObject(DASSANA_KEY);
    JSONObject normalize = dassana.getJSONObject(NORMALIZE);
    JSONObject generalContext = dassana.getJSONObject(GENERAL_CONTEXT);
    JSONObject policyContext = dassana.getJSONObject(POLICY_CONTEXT);

    Assertions.assertTrue(normalize.getString(WORKFLOW_ID).contentEquals("aws-config-via-security-hub"));
    Assertions.assertTrue(generalContext.getString(WORKFLOW_ID).contentEquals("general-context-aws"));
    Assertions.assertTrue(generalContext.getJSONObject("risk").getString("riskValue").contentEquals("low"));

    Assertions.assertTrue(policyContext.getString(WORKFLOW_ID).contentEquals("security-group-is-overly-permissive"));

    String response2 = helper.executeRunApi(helper.getFileContent("inputs/validAlertWithNoGeneralContext.json"),
        queryParams);


  }
  
  @Singleton
  @Replaces(EventBridgeHandler.class)
  public static class FakeEventBridgeHandler extends EventBridgeHandler {

    @Override
    public void handleEventBridge(ProcessingResponse processingResponse, String normalizerId) {
    }
  }


  @Singleton
  @Replaces(S3Manager.class)
  public static class FakeS3Manager extends S3Manager {

    @Override
    public String uploadedToS3(Optional<WorkflowOutputWithRisk> normalizationResult, String jsonToUpload) {
      return jsonToUpload;
    }
  }


  @Singleton
  @Replaces(RemoteContentDownloadApi.class)
  public static class FakeS3Downloader extends S3Downloader {


    public FakeS3Downloader(S3Client s3Client) {
      super(s3Client);
    }

    @Override
    public Optional<File> downloadContent(Long lastDownloaded) {
      return Optional.empty();
    }
  }


  @Singleton
  @Replaces(LambdaStepRunner.class)
  public static class MockLambdaStepRunner implements StepRunnerApi {

    public MockLambdaStepRunner() {
    }


    @Override
    public StepRunResponse runStep(Workflow workflow, Step step, String inputJson,
        String simpleOutputJsonStr) throws Exception {
      StepRunResponse stepRunResponse = new StepRunResponse();
      if (step.getId().contentEquals("resource-info")) {

        //not the best solution but here we simulate the dynamic nature of functions, i.e. based on the input, we
        // generate the response from lambda function

        JSONObject jsonObject = new JSONObject(inputJson);
        JSONObject testHintJsonObj = jsonObject.optJSONObject("test-hint");

        if (testHintJsonObj != null) {
          String resInfo = testHintJsonObj.optString("resource-info");
          if (StringUtils.isNotBlank(resInfo)) {
            stepRunResponse.setResponse(IOUtils.toString(
                Thread.currentThread().getContextClassLoader().getResourceAsStream(resInfo), Charset.defaultCharset()));
          }
        }


      }

      if (step.getId().contentEquals("getTags")) {
        stepRunResponse.setResponse(IOUtils.toString(
            Thread.currentThread().getContextClassLoader().getResourceAsStream("responses/tags.json"),
            Charset.defaultCharset()));
      }

      if (step.getId().contentEquals("list-of-attached-eni")) {
        stepRunResponse.setResponse(IOUtils.toString(
            Thread.currentThread().getContextClassLoader().getResourceAsStream("responses/list-of-attached-eni.json"),
            Charset.defaultCharset()));
      }

      if (step.getId().contentEquals("lookup")) {
        stepRunResponse.setResponse(IOUtils.toString(
            Thread.currentThread().getContextClassLoader().getResourceAsStream("responses/lookup.json"),
            Charset.defaultCharset()));

      }

      return stepRunResponse;
    }
  }

}
*/
