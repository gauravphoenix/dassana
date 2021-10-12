package app.dassana.core.launch;

import app.dassana.core.contentmanager.ContentManagerApi;
import app.dassana.core.launch.model.RunMode;
import app.dassana.core.restapi.Run;
import app.dassana.core.workflow.processor.RequestProcessor;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.function.aws.MicronautRequestHandler;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import javax.inject.Inject;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

@Introspected
public class SqsHandler extends MicronautRequestHandler<SQSEvent, Void> {

  private static final Logger logger = LoggerFactory.getLogger(SqsHandler.class);

  private final String dassanaDeadLetterQueue = System.getenv("dassanaDeadLetterQueue");

  @Inject private ContentManagerApi contentManager;
  @Inject private RequestProcessor requestProcessor;
  @Inject private SqsClient sqsClient;
  @Inject private Run run;


  @Override
  public Void execute(SQSEvent input) {

    List<SQSMessage> sqsMessages = input.getRecords();

    for (SQSMessage message : sqsMessages) {
      try {
        String body = message.getBody();
        JSONObject jsonObject = new JSONObject(body);
        run.processAlert(jsonObject, null, true, RunMode.PROD,true);
      } catch (Exception e) {
        handleException(e, message.getBody());
      }


    }

    return null;

  }

  private void handleException(Exception exception, String originalInput) {

    logger.error("Error in processing message: ", exception);
    JSONObject jsonObject = new JSONObject(originalInput);

    //get stack trace from the exception and put it in the "error" json key
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    exception.printStackTrace(pw);
    jsonObject.put("error", sw.toString());

    sqsClient.sendMessage(
        SendMessageRequest.builder().queueUrl(dassanaDeadLetterQueue)
            .messageBody(jsonObject.toString())
            .build());


  }


}
