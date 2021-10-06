package app.dassana.core.contentmanager;

import static app.dassana.core.contentmanager.ContentManager.GENERAL_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.NORMALIZE;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT_CAT;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT_CLASS;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT_SUBCLASS;
import static app.dassana.core.contentmanager.ContentManager.POLICY_CONTEXT_SUB_CAT;
import static app.dassana.core.contentmanager.ContentManager.RESOURCE_CONTEXT;

import app.dassana.core.api.DassanaWorkflowValidationException;
import app.dassana.core.normalize.model.NormalizerWorkflow;
import app.dassana.core.policycontext.model.PolicyContext;
import app.dassana.core.resource.model.GeneralContext;
import app.dassana.core.resource.model.ResourceContext;
import app.dassana.core.risk.model.RiskConfig;
import app.dassana.core.risk.model.Rule;
import app.dassana.core.rule.MatchType;
import app.dassana.core.workflow.model.Filter;
import app.dassana.core.workflow.model.Output;
import app.dassana.core.workflow.model.Step;
import app.dassana.core.workflow.model.ValueType;
import app.dassana.core.workflow.model.VendorFilter;
import app.dassana.core.workflow.model.Workflow;
import io.micronaut.core.util.StringUtils;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.inject.Singleton;
import org.json.JSONArray;
import org.json.JSONObject;

@Singleton
public class Parser {

  public static final String MISSING_NORMALIZATION_MSG = "Dassana couldn't normalize the alert you sent, please verify "
      + "normalizers filter config";


  PolicyContext getPolicyContext(JSONObject jsonObject) {

    PolicyContext policyContext = new PolicyContext();
    policyContext.setAlertClass(jsonObject.optString("class"));
    policyContext.setSubClass(jsonObject.optString("subclass"));
    policyContext.setCategory(jsonObject.optString("category"));
    policyContext.setSubCategory(jsonObject.optString("subcategory"));

    return policyContext;


  }


  public Workflow getWorkflow(JSONObject jsonObject) {
    Workflow workflow = new Workflow();

    String type = jsonObject.optString("type");

    if (StringUtils.isNotEmpty(type) && type.contentEquals(NORMALIZE)) {
      workflow = new NormalizerWorkflow();

      ((NormalizerWorkflow) workflow).setVendorId(jsonObject.getString("vendor-id"));

      JSONObject postProcessor = jsonObject.optJSONObject("post-processor");

      List<Step> postProcessorSteps = new LinkedList<>();

      if (postProcessor != null) {
        JSONArray postProcessorStepsJsonArray = postProcessor.optJSONArray("steps");

        if (postProcessorStepsJsonArray != null) {
          for (int i = 0; i < postProcessorStepsJsonArray.length(); i++) {
            JSONObject stepsJSONObject = postProcessorStepsJsonArray.getJSONObject(i);
            Step step = new Step();
            step.setId(stepsJSONObject.getString("id"));
            step.setUses(stepsJSONObject.getString("uses"));
            postProcessorSteps.add(step);
          }
        }
      }
      ((NormalizerWorkflow) workflow).setPostProcessorSteps(postProcessorSteps);


    } else if (type.contentEquals(POLICY_CONTEXT)) {
      workflow = getPolicyContext(jsonObject);
      ((PolicyContext) workflow).setAlertClass(jsonObject.optString(POLICY_CONTEXT_CLASS));
      ((PolicyContext) workflow).setSubClass(jsonObject.optString(POLICY_CONTEXT_SUBCLASS));
      ((PolicyContext) workflow).setCategory(jsonObject.optString(POLICY_CONTEXT_CAT));
      ((PolicyContext) workflow).setSubCategory(jsonObject.optString(POLICY_CONTEXT_SUB_CAT));
      ((PolicyContext) workflow).setRiskConfig(getRiskConfig(jsonObject));

      PolicyContext policyContext = (PolicyContext) workflow;
      policyContext.setVendorFilters(getFilters(jsonObject));


    } else if (type.contentEquals(GENERAL_CONTEXT)) {
      workflow = new GeneralContext();
      ((GeneralContext) workflow).setCsp(jsonObject.getString("csp"));
      ((GeneralContext) workflow).setRiskConfig(getRiskConfig(jsonObject));
    } else if (type.contentEquals(RESOURCE_CONTEXT)) {
      workflow = new ResourceContext();
      ((ResourceContext) workflow).setService(jsonObject.getString("service"));
      ((ResourceContext) workflow).setResourceType(jsonObject.getString("resource-type"));
      ((ResourceContext) workflow).setRiskConfig(getRiskConfig(jsonObject));
    } else {

      String errorMsg = String.format(
          "Sorry, we don't recognize workflow type %s, valid workflow types are %s,%s,%s and %s", type,
          NORMALIZE, GENERAL_CONTEXT, RESOURCE_CONTEXT, POLICY_CONTEXT);

      throw new DassanaWorkflowValidationException(errorMsg);
    }

    workflow.setSchema(jsonObject.getInt("schema"));
    workflow.setType(jsonObject.getString("type"));
    workflow.setId(jsonObject.getString("id"));
    workflow.setName(jsonObject.optString("name"));
    JSONArray labels = jsonObject.optJSONArray("labels");
    if (labels != null) {
      var labelsArray = new LinkedList<String>();
      for (int i = 0; i < labels.length(); i++) {
        labelsArray.add(labels.getString(i));
      }
      workflow.setLabels(labelsArray);
    }

    workflow.setOutput(getOutputs(jsonObject));
    workflow.setSteps(getSteps(jsonObject));

    if (!workflow.getType().equals(POLICY_CONTEXT)) {

      List<VendorFilter> filters = getFilters(jsonObject);
      List<Filter> filterList = new LinkedList<>();
      for (VendorFilter filter : filters) {
        Filter simpleFilter = new Filter();
        simpleFilter.setRules(filter.getRules());
        simpleFilter.setMatchType(filter.getMatchType());
        filterList.add(simpleFilter);
      }

      workflow.setFilters(filterList);

    }

    return workflow;


  }

  RiskConfig getRiskConfig(JSONObject workFlowJson) {

    RiskConfig riskConfig = new RiskConfig();
    List<Rule> riskRules = new LinkedList<>();

    JSONObject riskConfigObj = workFlowJson.optJSONObject("risk-config");

    if (riskConfigObj != null) {
      riskConfig.setDefaultRisk(riskConfigObj.getString("default-risk"));
      JSONArray rulesJsonArray = riskConfigObj.optJSONArray("rules");

      if (rulesJsonArray != null) {
        for (int i = 0; i < rulesJsonArray.length(); i++) {
          JSONObject ruleObj = rulesJsonArray.getJSONObject(i);
          String name = ruleObj.getString("name");
          String condition = ruleObj.getString("condition");
          String risk = ruleObj.getString("risk");

          Rule rule = new Rule(name, condition, risk);
          riskRules.add(rule);

        }
        riskConfig.setRiskRules(riskRules);
      }


    }
    return riskConfig;

  }

  private List<Step> getSteps(JSONObject jsonObject) {

    JSONArray steps = jsonObject.optJSONArray("steps");

    List<Step> stepSet = new LinkedList<>();

    if (steps != null) {
      for (int i = 0; i < steps.length(); i++) {
        JSONObject stepsJSONObject = steps.getJSONObject(i);
        Step step = new Step();
        step.setId(stepsJSONObject.getString("id"));
        step.setUses(stepsJSONObject.getString("uses"));

        JSONArray withKey = stepsJSONObject.optJSONArray("with");

        if (withKey != null) {
          List<Map<String, String>> fields = new LinkedList<>();

          for (int j = 0; j < withKey.length(); j++) {

            JSONObject kvp = withKey.getJSONObject(j);

            Map<String, String> field = new HashMap<>();
            field.put("name", kvp.getString("name"));
            field.put("value", kvp.getString("value"));
            field.put("value-type", kvp.optString("value-type"));
            fields.add(field);
          }
          step.setFields(fields);

        } else {
          step.setFields(new LinkedList<>());
        }

        stepSet.add(step);

      }
    }
    return stepSet;

  }

  private List<VendorFilter> getFilters(JSONObject jsonObject) {
    List<VendorFilter> filters = new LinkedList<>();

    JSONArray optJSONArray = jsonObject.optJSONArray("filters");
    if (optJSONArray != null) {
      for (int i = 0; i < optJSONArray.length(); i++) {
        VendorFilter filter = new VendorFilter();
        JSONObject filterObj = optJSONArray.getJSONObject(i);
        String matchType = filterObj.getString("match-type");
        if (matchType.toLowerCase().contentEquals("any")) {
          filter.setMatchType(MatchType.ANY);
        } else if (matchType.toLowerCase().contentEquals("all")) {
          filter.setMatchType(MatchType.ALL);
        } else {
          throw new IllegalArgumentException("Unrecognized filter type ".concat(matchType));
        }
        JSONArray rulesJsonArray = filterObj.optJSONArray("rules");
        List<String> rules = new LinkedList<>();
        if (rulesJsonArray != null) {
          for (int j = 0; j < rulesJsonArray.length(); j++) {
            String rule = rulesJsonArray.optString(j);
            rules.add(rule);
          }
        }

        filter.setRules(rules);
        filters.add(filter);
      }

    }
    return filters;

  }

  private List<Output> getOutputs(JSONObject jsonObject) {

    List<Output> outputs = new LinkedList<>();
    JSONArray optOutputJsonArray = jsonObject.optJSONArray("output");
    if (optOutputJsonArray != null) {
      for (int i = 0; i < optOutputJsonArray.length(); i++) {
        JSONObject outputObj = optOutputJsonArray.getJSONObject(i);
        Output output = new Output();
        output.setValue(outputObj.getString("value"));
        output.setName(outputObj.getString("name"));
        String valueType = outputObj.optString("value-type");
        if (StringUtils.isEmpty(valueType)) {
          output.setValueType(ValueType.JQ_EXPRESSION);
        } else {
          output.setValueType(ValueType.valueOf(valueType));
        }
        outputs.add(output);
      }

    }
    return outputs;

  }
}
