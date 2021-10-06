package app.dassana.core.restapi;

import static app.dassana.core.contentmanager.infra.S3Manager.LAST_UPDATED_KEY;
import static app.dassana.core.contentmanager.infra.S3Manager.WORKFLOW_PATH_IN_S3;

import app.dassana.core.contentmanager.ContentManager;
import app.dassana.core.contentmanager.Parser;
import app.dassana.core.launch.model.Request;
import app.dassana.core.util.StringyThings;
import app.dassana.core.workflow.model.Workflow;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.QueryValue;
import java.nio.charset.Charset;
import java.util.Set;
import javax.inject.Inject;
import org.json.JSONObject;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Controller("/workflows")
public class Workflows {

  @Inject private S3Client s3Client;

  @Inject private ContentManager contentManager;
  @Inject private Parser parser;

  String dassanaBucket = System.getenv().get("dassanaBucket");


  @Delete
  void handleDelete(@QueryValue("workflowId") String workFlowId) {

    String key = WORKFLOW_PATH_IN_S3.concat(workFlowId);
    s3Client.deleteObject(DeleteObjectRequest.builder().bucket(dassanaBucket).key(key).build());

    s3Client.putObject(PutObjectRequest.builder().bucket(dassanaBucket).key(LAST_UPDATED_KEY).build(),
        RequestBody.empty());


  }


  @Get(produces = MediaType.APPLICATION_YAML)
  HttpResponse<String> handleGet(@QueryValue("workflowId") String workFlowId,
      @QueryValue("default") @Nullable Boolean getDefault) throws Exception {

    if (getDefault == null) {
      getDefault = Boolean.FALSE;
    }

    if (getDefault) {//user wants to get the default dassana workflow, so we only look for workflows in the default
      // content set
      Set<Workflow> defaultWorkflowSet = contentManager.getDefaultWorkflowSet();

      for (Workflow workflow : defaultWorkflowSet) {
        if (workflow.getId().contentEquals(workFlowId)) {
          return HttpResponse.ok().body(workflow.getWorkflowFileContent()).
              header("x-workflow-is-default", "true");
        }
      }

    } else {
      Request request = new Request(null);
      request.setUseCache(false);

      Set<Workflow> workflowSet = contentManager.getWorkflowSet(new Request(null));
      for (Workflow workflow : workflowSet) {
        if (workflow.getId().contentEquals(workFlowId)) {
          String isDefault = "true";
          if (!workflow.isDefault()) {
            isDefault = "false";
          }
          return HttpResponse.ok().body(workflow.getWorkflowFileContent()).header("x-workflow-is-default", isDefault);
        }
      }
    }
    return HttpResponse.notFound();

  }


  @Post(consumes = MediaType.APPLICATION_YAML)
  void handleSaveToS3(@Body String body) throws JsonProcessingException {
    Workflow workflow = parser.getWorkflow(new JSONObject(StringyThings.getJsonFromYaml(body)));
    String key = WORKFLOW_PATH_IN_S3.concat(workflow.getId());
    PutObjectRequest putObjectRequest = PutObjectRequest.builder().bucket(dassanaBucket).key(key).build();
    s3Client.putObject(putObjectRequest, RequestBody.fromString(body, Charset.defaultCharset()));

    s3Client.putObject(PutObjectRequest.builder().bucket(dassanaBucket).key(LAST_UPDATED_KEY).build(),
        RequestBody.empty());

  }

}
