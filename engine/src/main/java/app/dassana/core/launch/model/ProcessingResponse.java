package app.dassana.core.launch.model;

import app.dassana.core.normalize.model.NormalizerWorkflow;

public class ProcessingResponse {

  public ProcessingResponse(Request request) {
    this.request = request;
  }

  Request request;
  String decoratedJson;
  NormalizerWorkflow normalizerWorkflow;

  public Request getRequest() {
    return request;
  }

  public void setRequest(Request request) {
    this.request = request;
  }

  public NormalizerWorkflow getNormalizerWorkflow() {
    return normalizerWorkflow;
  }

  public void setNormalizerWorkflow(NormalizerWorkflow normalizerWorkflow) {
    this.normalizerWorkflow = normalizerWorkflow;
  }

  public String getDecoratedJson() {
    return decoratedJson;
  }

  public void setDecoratedJson(String decoratedJson) {
    this.decoratedJson = decoratedJson;
  }
}
