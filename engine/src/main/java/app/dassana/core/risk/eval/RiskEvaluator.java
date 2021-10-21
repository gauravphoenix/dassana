//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package app.dassana.core.risk.eval;

import app.dassana.core.contentmanager.ContentManager;
import app.dassana.core.risk.model.Risk;
import app.dassana.core.risk.model.Rule;
import app.dassana.core.risk.model.SubRule;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.inject.Singleton;
import net.thisptr.jackson.jq.BuiltinFunctionLoader;
import net.thisptr.jackson.jq.JsonQuery;
import net.thisptr.jackson.jq.Scope;
import net.thisptr.jackson.jq.Version;
import net.thisptr.jackson.jq.Versions;
import org.json.JSONObject;

@Singleton
public class RiskEvaluator {

  public RiskEvaluator() {
    BuiltinFunctionLoader.getInstance().loadFunctions(Versions.JQ_1_6, rootScope);
  }

  Scope rootScope = Scope.newEmptyScope();
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // a string array to hold the risk severities in descending order (from critical to low)
  private static final String[] riskValues = new String[]{ContentManager.RISKS.CRITICAL.getSeverity(),
    ContentManager.RISKS.HIGH.getSeverity(), ContentManager.RISKS.MEDIUM.getSeverity(), ContentManager.RISKS.LOW.getSeverity(),
    ContentManager.RISKS.ACCEPTED.getSeverity(), ContentManager.RISKS.EMPTY.getSeverity()};

  public Risk evaluate(RiskEvalRequest input) {
    Risk risk = new Risk(); // holds the rule risk
    Risk tempRisk = new Risk(); // holds the sub-rule risk - tempRisk has precedence over risk
    String defaultRisk = input.getDefaultRisk();
    risk.setRiskValue(defaultRisk);
    risk.setId("default");
    List<Rule> riskRules = input.getRiskRules();

    // map to hold the rules. key -> severity | value -> list of rules with same severity
    HashMap<String, List<Rule>> map = new HashMap<>();

    for (app.dassana.core.risk.model.Rule riskRule : riskRules) {
      String condition = riskRule.getCondition();
      try {

        JsonQuery jsonQuery = JsonQuery.compile(condition, Version.LATEST);
        Scope childScope = Scope.newChildScope(rootScope);
        JSONObject jsonObject = new JSONObject(input.getJsonData());
        JsonNode in = MAPPER.readTree(jsonObject.toString());
        AtomicBoolean result = new AtomicBoolean(false);
        jsonQuery.apply(childScope, in, jsonNode -> result.set(jsonNode.asBoolean()));

        // if the rule matches
        if (result.get()) {

          List<SubRule> subRules = riskRule.getSubRules();

          for (app.dassana.core.risk.model.SubRule subRule : subRules) {
            String subRiskCondition = subRule.getSubRiskCondition();
            try {

              JsonQuery subJsonQuery = JsonQuery.compile(subRiskCondition, Version.LATEST);
              Scope subChildScope = Scope.newChildScope(rootScope);
              JSONObject subJsonObject = new JSONObject(input.getJsonData());
              JsonNode subIn = MAPPER.readTree(subJsonObject.toString());
              AtomicBoolean subResult = new AtomicBoolean(false);
              subJsonQuery.apply(subChildScope, subIn, jsonNode -> subResult.set(jsonNode.asBoolean()));

              if (subResult.get()) {
                Rule subRisk = new Rule(subRule.getSubRiskId(), subRule.getSubRiskCondition(), subRule.getSubRisk(), true, null);


                // if there has been a same severity match
                if (map.containsKey(subRisk.getRisk())) {
                  map.get(subRisk.getRisk()).add(subRisk);
                  map.put(subRisk.getRisk(), map.get(subRisk.getRisk()));
                } else { // new risk severity
                  List<Rule> ruleTemp = new LinkedList<>();
                  ruleTemp.add(subRisk);
                  map.put(subRisk.getRisk(), ruleTemp);
                }
              }

            } catch (Exception e) {
              throw new RiskEvalException(String.format("Unable to match subrule %s condition %s", subRule.getSubRiskId(),
                  subRule.getSubRiskCondition()), e, riskRule.getId());
            }
          }

          // if there has been a same severity match
          if (map.containsKey(riskRule.getRisk())) {
            riskRule.setIsSubRule(false);
            map.get(riskRule.getRisk()).add(riskRule);
            map.put(riskRule.getRisk(), map.get(riskRule.getRisk()));
          } else { // new risk severity
            List<Rule> ruleTemp = new LinkedList<>();
            ruleTemp.add(riskRule);
            map.put(riskRule.getRisk(), ruleTemp);
          }
        }
      } catch (Exception e) {
        throw new RiskEvalException(String.format("Unable to match rule %s condition %s", riskRule.getId(),
            riskRule.getCondition()),e, risk.getId());
      }
    }

    List<String> matched = new LinkedList<>();
    Boolean isSubRuleFound = false;
    Boolean isMainRuleFound = false;
    Boolean riskFound = false; // whether a higher risk has been found

    // to find the matching risk with the highest severity
    for (String rv : riskValues) { // parse through the severity array
      if (map.containsKey(rv)) { // if any of the matched rules have the same severity

        // need to parse through the array of matched risks with same severity to determine if it is sub-rule
        List<Rule> sameSeverityRules = map.get(rv); // list of matched rules with same severity
        for (app.dassana.core.risk.model.Rule ssr : sameSeverityRules) {
          if (!riskFound && ssr.getIsSubRule() && !isSubRuleFound) { // if it's sub-rule; and it hasn't been matched before
            tempRisk.setRiskValue(ssr.getRisk());
            tempRisk.setId(ssr.getId());
            tempRisk.setCondition(ssr.getCondition());

            isSubRuleFound = true; // to prevent overwriting of the already matched sub-rule
          } else if (!riskFound && !ssr.getIsSubRule() && !isMainRuleFound) { // if it's main-rule; and it hasn't been matched before
            risk.setRiskValue(ssr.getRisk());
            risk.setId(ssr.getId());
            risk.setCondition(ssr.getCondition());

            isMainRuleFound = true; // to prevent overwriting of the already matched sub-rule
          } else { // once either sub-rule or rule have matched no need to re-match them
            matched.add(ssr.getId());
          }
        }

        // to prevent the lower severity risks from overwriting the higher severity ones
        if (isMainRuleFound || isSubRuleFound) {
          riskFound = true;
        }

        // breaks the for loop once we found the highest severity risk
        // break; // no need for break anymore since we need to generate a list of matched rule ids
      }
    }

    if (isSubRuleFound) {
      if (isMainRuleFound) { // since sub-rule takes precedence we add the id of the main rule to the matched list
        matched.add(risk.getId());
      }
      risk = tempRisk; // sub-rule takes precedence
    }

    return risk;
  }
}
