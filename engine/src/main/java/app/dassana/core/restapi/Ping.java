package app.dassana.core.restapi;

import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import java.io.IOException;
import org.apache.commons.lang3.RandomUtils;

@Controller
public class Ping {

  private final String[] responseStr = new String[]{"A termite walks into the bar and asks, ‘Is the bar tender here?’",
      "People who use selfie sticks really need to have a good, long look at themselves.",
      "Why do bees have sticky hair? Because they use a honeycomb.",
      "Just burned 2,000 calories. That’s the last time I leave brownies in the oven while I nap.",
      "I’m reading a book about anti-gravity. It’s impossible to put down."};

  @Get("/ping")
  @Produces("text/plain")
  public String getPingResponse() throws IOException {
    return responseStr[RandomUtils.nextInt(0, responseStr.length)];
  }


}
