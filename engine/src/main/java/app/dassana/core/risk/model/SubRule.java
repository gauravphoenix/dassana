package app.dassana.core.risk.model;

public class SubRule {
  String id;
  String condition;
  String risk;

  public SubRule(String id, String condition, String risk) {
    this.id = id;
    this.condition = condition;
    this.risk = risk;
  }

  public String getSubRisk() {
    return risk;
  }

  public void setSubRisk(String risk) {
    this.risk = risk;
  }

  public String getSubRiskId() {
    return id;
  }

  public void setSubRiskId(String id) {
    this.id = id;
  }

  public String getSubRiskCondition() {
    return condition;
  }

  public void setSubRiskCondition(String condition) {
    this.condition = condition;
  }
}