package app.dassana.core.restapi;

import com.amazonaws.serverless.exceptions.ContainerInitializationException;
import io.micronaut.context.ApplicationContextBuilder;
import io.micronaut.function.aws.proxy.MicronautLambdaHandler;
import io.micronaut.runtime.Micronaut;

public class Application extends MicronautLambdaHandler {

  public Application() throws ContainerInitializationException {
  }

  public Application(ApplicationContextBuilder applicationContextBuilder)
      throws ContainerInitializationException {
    super(applicationContextBuilder);
  }

  public static void main(String[] args) {
    Micronaut.run(Application.class, args);
  }
}
