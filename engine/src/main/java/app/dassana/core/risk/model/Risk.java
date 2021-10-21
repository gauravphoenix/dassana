package app.dassana.core.risk.model;

import java.util.List;

public class Risk {
  String id = "";
  String riskValue = "";
  String condition = "";
  List<String> matched; // list object to hold matched risks with lower severity than main riskValue

  public String getCondition() {
    return condition;
  }

  public void setCondition(String condition) {
    this.condition = condition;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getRiskValue() {
    return riskValue;
  }

  public void setRiskValue(String riskValue) {
    this.riskValue = riskValue;
  }

  public List<String> getMatchedRisks() {
    return matched;
  }

  public void setMatchedRisks(List<String> matched) {
    this.matched = matched;
  }
}
