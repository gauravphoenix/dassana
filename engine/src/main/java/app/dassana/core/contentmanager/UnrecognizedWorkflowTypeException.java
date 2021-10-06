package app.dassana.core.contentmanager;

public class UnrecognizedWorkflowTypeException extends RuntimeException{

  public UnrecognizedWorkflowTypeException() {
  }

  public UnrecognizedWorkflowTypeException(String message) {
    super(message);
  }

  public UnrecognizedWorkflowTypeException(String message, Throwable cause) {
    super(message, cause);
  }

  public UnrecognizedWorkflowTypeException(Throwable cause) {
    super(cause);
  }

  public UnrecognizedWorkflowTypeException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
