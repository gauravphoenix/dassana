package app.dassana.core.workflow.model;

public class WorkflowOutputException extends RuntimeException{

  String outputField;

  public String getOutputField() {
    return outputField;
  }

  public void setOutputField(String outputField) {
    this.outputField = outputField;
  }

  public WorkflowOutputException() {
  }

  public WorkflowOutputException(String message) {
    super(message);
  }

  public WorkflowOutputException(String message, Throwable cause) {
    super(message, cause);
  }

  public WorkflowOutputException(Throwable cause) {
    super(cause);
  }

  public WorkflowOutputException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
