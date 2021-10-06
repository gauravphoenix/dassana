package app.dassana.core.contentmanager.model;

public class SyncResult {


  boolean successful;
  boolean cacheHit;
  long contentLastSyncTimeMs;

  public long getContentLastSyncTimeMs() {
    return contentLastSyncTimeMs;
  }

  public void setContentLastSyncTimeMs(long contentLastSyncTimeMs) {
    this.contentLastSyncTimeMs = contentLastSyncTimeMs;
  }

  public boolean isSuccessful() {
    return successful;
  }

  public void setSuccessful(boolean successful) {
    this.successful = successful;
  }

  public boolean isCacheHit() {
    return cacheHit;
  }

  public void setCacheHit(boolean cacheHit) {
    this.cacheHit = cacheHit;
  }
}
