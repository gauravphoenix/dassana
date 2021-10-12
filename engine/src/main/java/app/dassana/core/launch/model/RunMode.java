package app.dassana.core.launch.model;

public enum RunMode {
  TEST, ////dassana will NOT post alerts to the custom eventbridge bus
  PROD //dassana will post alerts to the custom eventbridge bus
}
