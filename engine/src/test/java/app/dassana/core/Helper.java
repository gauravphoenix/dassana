package app.dassana.core;

import java.io.IOException;
import java.nio.charset.Charset;
import org.apache.commons.io.IOUtils;

public class Helper {


  public static String getInputFromFile(String fileName) throws IOException {

    return IOUtils.toString(
        Thread.currentThread().getContextClassLoader().getResourceAsStream("inputs/".concat(fileName)),
        Charset.defaultCharset());

  }

}
