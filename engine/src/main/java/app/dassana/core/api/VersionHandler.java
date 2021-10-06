package app.dassana.core.api;

import app.dassana.core.util.StringyThings;
import com.jayway.jsonpath.JsonPath;
import com.vdurmont.semver4j.Semver;
import java.io.IOException;
import java.nio.charset.Charset;
import javax.inject.Singleton;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

@Singleton
public class VersionHandler {

  CloseableHttpClient httpClient = HttpClients.createDefault();

  public VersionResponse getVersionResponse() throws IOException {
    String json = StringyThings.getJsonFromYaml(getLatestVersion());

    String latestVersion = JsonPath.read(json, "$.Resources.DassanaEngineApi.Properties.Environment.Variables.version");
    String currentVersion = System.getenv().get("version");
    if (currentVersion == null) {//this means that most like we are running the api server locally
      VersionResponse versionResponse = new VersionResponse();
      versionResponse.setInstalledVersion("0.0.0");
      versionResponse.setMessage("local-dev-server");
      versionResponse.setUpgradeAvailable(false);
      return versionResponse;
    }

    VersionResponse versionResponse = new VersionResponse();
    versionResponse.setInstalledVersion(currentVersion);

    if (!"__version-to-be-replaced-by-cicd__".equals(currentVersion)) {
      Semver installed = new Semver(currentVersion);
      Semver latest = new Semver(latestVersion);

      if (latest.isGreaterThan(installed)) {
        versionResponse.setUpgradeAvailable(true);
        versionResponse.setMessage("Hey there! An upgrade to Dassana is available. Please visit https://docs.dassana"
            + ".io/docs/guides/ops/updating-dassana for instructions");
      } else {
        versionResponse.setUpgradeAvailable(false);
      }
    }
    return versionResponse;


  }


  private String getLatestVersion() throws IOException {
    HttpGet request = new HttpGet("https://s3.amazonaws.com/dassana-prod-oss-public.dassana.io/latest/cft.yaml");
    try (CloseableHttpResponse response = httpClient.execute(request)) {
      if (response.getStatusLine().getStatusCode() == 200) {
        return IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
      } else {
        throw new RuntimeException(
            "Github API failed :( with response code ".concat(response.getStatusLine().getReasonPhrase()));
      }

    }
  }

}
