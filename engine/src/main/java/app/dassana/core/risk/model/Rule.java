package app.dassana.core.risk.model;
import java.util.LinkedList;
import java.util.List;

public class Rule {

  String id;
  String condition;
  String risk;
  Boolean isSubRule;

  // list object to hold all the sub-rules associated with a rule
  List<SubRule> subRules;

  public Rule(String id, String condition, String risk, Boolean isSubRule, List<SubRule> subRules) {
    this.id = id;
    this.condition = condition;
    this.risk = risk;
    this.isSubRule = isSubRule;
    this.subRules = subRules;
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

  public void setId(String id) {
    this.id = id;
  }

  public String getCondition() {
    return condition;
  }

  public void setCondition(String condition) {
    this.condition = condition;
  }

  public List<SubRule> getSubRules() {
    if (subRules == null) {
      return new LinkedList<>();
    }
    return this.subRules;
  }

  public void setSubRules(List<SubRule> subRules) {
    this.subRules = subRules;
  }

  public Boolean getIsSubRule() {return isSubRule;}

  public void setIsSubRule(Boolean isSubRule) {this.isSubRule = isSubRule;}
}
