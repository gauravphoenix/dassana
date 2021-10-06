package app.dassana.core.restapi;

import io.micronaut.runtime.Micronaut;

/**
 * Use this local sever to run Dassana Engine REST API as if you have deployed it to the API Gateway.
 * <p>
 * This enables faster iteration/debugging as you don't have to run the build script which packages everything and then
 * deploys the entire stack.
 * <p>
 * Note that it is assumed that you have deployed the stack at-least once Also, only the rest api is running locally,
 * Dassana Actions (normalizer etc) are still invoked on AWS side
 * <p>
 * following env vars must be set before you run this-
 * <p>
 * <b>AWS_REGION</b> --> region like us-east-1 etc
 * <p>
 * <b>DASSANA_STACK_NAME</b> --> the name of the stack that you deployed already
 * <p>
 * <b>dassanaBucket</b> --> you can get this value from the CFT stack. Look for * "DassanaBucket" logical resource under
 * the
 * resources ta
 * <p>
 * <b>dassanaEventBridgeBusName</b> --> much like dassanaBucket. Look for "DassanaEventBus" logical resource under the
 * *
 * *resources tab
 * </p>
 */
public class LocalServer {

  public static void main(String[] args) {
    Micronaut.run(Application.class, args);
  }

}
