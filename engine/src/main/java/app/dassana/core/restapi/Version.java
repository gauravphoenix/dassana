package app.dassana.core.restapi;

import app.dassana.core.api.VersionHandler;
import app.dassana.core.api.VersionResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import java.io.IOException;
import javax.inject.Inject;

@Controller("/version")
public class Version {

  @Inject private VersionHandler versionHandler;

  @Get
  VersionResponse getVersion() throws IOException {
    return versionHandler.getVersionResponse();
  }


}
