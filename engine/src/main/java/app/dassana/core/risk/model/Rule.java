package app.dassana.core.risk.model;
import java.util.List;

public class Rule {

  String id;
  String condition;
  String risk;
  List<SubRule> subRules;  // list object to hold all the sub-rules associated with a rule

  public Rule(String id, String condition, String risk) {
    this.id = id;
    this.condition = condition;
    this.risk = risk;
  }

  public String getRisk() {
    return risk;
  }

  public void setRisk(String risk) {
    this.risk = risk;
  }

  public String getId() {
    return id;
  }

  public void setName(String id) {
    this.id = id;
  }

  public String getCondition() {
    return condition;
  }

  public void setCondition(String condition) {
    this.condition = condition;
  }
}
