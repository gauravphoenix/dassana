package app.dassana.core.contentmanager;

import java.util.List;
import java.util.concurrent.ExecutionException;

public interface RemoteContentDownloadApi {

  List<String> downloadContent();

  Long getLastUpdated(boolean useCache) throws ExecutionException;

}
