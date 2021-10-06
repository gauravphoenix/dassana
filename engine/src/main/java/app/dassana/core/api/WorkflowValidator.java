package app.dassana.core.api;

import app.dassana.core.api.linter.BaseLinter;
import app.dassana.core.api.linter.GeneralLinter;
import app.dassana.core.api.linter.NormalizeLinter;
import app.dassana.core.api.linter.PolicyLinter;
import app.dassana.core.api.linter.ResourceLinter;
import app.dassana.core.contentmanager.ContentManager;
import app.dassana.core.contentmanager.Parser;
import app.dassana.core.launch.model.Message;
import app.dassana.core.launch.model.Severity;
import app.dassana.core.normalize.model.NormalizerWorkflow;
import app.dassana.core.policycontext.model.PolicyContext;
import app.dassana.core.resource.model.GeneralContext;
import app.dassana.core.resource.model.ResourceContext;
import app.dassana.core.rule.RuleMatch;
import app.dassana.core.workflow.model.Filter;
import app.dassana.core.workflow.model.Workflow;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.LinkedList;
import java.util.List;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.apache.commons.io.IOUtils;
import org.everit.json.schema.Schema;
import org.everit.json.schema.ValidationException;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;

@Singleton
public class WorkflowValidator {

  @Inject ContentManager contentManager;
  @Inject RuleMatch ruleMatch;
  @Inject Parser parser;
  private SchemaLoader schemaLoader;
  private final NormalizeLinter normalizeLinter = new NormalizeLinter();
  private final GeneralLinter generalLinter = new GeneralLinter();
  private final ResourceLinter resourceLinter = new ResourceLinter();
  private final PolicyLinter policyLinter = new PolicyLinter();

  public WorkflowValidator() throws IOException {
    initLinters();
  }

  void validateJsonAgainstJsonSchema(String json, String jsonSchema) {

    JSONObject baseSchema = new JSONObject(jsonSchema);
    Schema schema = SchemaLoader.load(baseSchema);
    try {
      schema.validate(new JSONObject(json));
    } catch (org.everit.json.schema.ValidationException e) {
      List<Message> messasges = new LinkedList<>();
      List<ValidationException> causingExceptions = e.getCausingExceptions();
      causingExceptions.forEach(e1 -> messasges.add(new Message(e1.getMessage())));
      DassanaWorkflowValidationException dassanaWorkflowValidationException = new DassanaWorkflowValidationException();
      dassanaWorkflowValidationException.setMessages(messasges);
      if (dassanaWorkflowValidationException.getMessages().size() > 0) {
        throw dassanaWorkflowValidationException;
      }
    }


  }

  private void initLinters() throws IOException {
    normalizeLinter.init();
    generalLinter.init();
    resourceLinter.init();
    policyLinter.init();
  }

  private void processJson(BaseLinter linter, String json) throws IOException {
    List<Message> messages = linter.validate(json);
    if (messages.size() > 0) {
      DassanaWorkflowValidationException workflowException = new DassanaWorkflowValidationException();
      workflowException.setMessages(messages);
      throw workflowException;
    }
  }

  public void handleValidate(String workflowAsJson) throws IOException {

    Workflow workflow;
    try {
      JSONObject jsonObject = new JSONObject(workflowAsJson);
      workflow = parser.getWorkflow(jsonObject);
    } catch (Exception e) {
      DassanaWorkflowValidationException dassanaWorkflowValidationException = new DassanaWorkflowValidationException();
      List<Message> messages = new LinkedList<>();
      messages.add(new Message(e.getMessage(), Severity.ERROR));
      dassanaWorkflowValidationException.setMessages(messages);
      throw dassanaWorkflowValidationException;
    }

    //todo: clean it up: the schemas should be loaded on init and not everytime

    //let's validate against base schema first
    String baseSchema = IOUtils.toString(Thread.currentThread().getContextClassLoader()
        .getResourceAsStream("content/schemas/base-workflow-schema.json"), Charset.defaultCharset());

    validateJsonAgainstJsonSchema(workflowAsJson, baseSchema);

    if (workflow instanceof NormalizerWorkflow) {
      String normalizerSchema = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("content/schemas/normalizer-schema.json"), Charset.defaultCharset());
      validateJsonAgainstJsonSchema(workflowAsJson, normalizerSchema);
      processJson(normalizeLinter, workflowAsJson);
    } else if (workflow instanceof PolicyContext) {
      String generalContextSchema = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("content/schemas/risk-schema.json"), Charset.defaultCharset());
      validateJsonAgainstJsonSchema(workflowAsJson, generalContextSchema);
      processJson(policyLinter, workflowAsJson);
    } else if (workflow instanceof ResourceContext) {
      String resourceContextSchema = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("content/schemas/resource-context-schema.json"), Charset.defaultCharset());
      validateJsonAgainstJsonSchema(workflowAsJson, resourceContextSchema);
      processJson(resourceLinter, workflowAsJson);
    } else if (workflow instanceof GeneralContext) {
      String generalContextSchema = IOUtils.toString(Thread.currentThread().getContextClassLoader()
          .getResourceAsStream("content/schemas/risk-schema.json"), Charset.defaultCharset());
      validateJsonAgainstJsonSchema(workflowAsJson, generalContextSchema);
      processJson(generalLinter, workflowAsJson);
    }

    for (Filter filter : workflow.getFilters()) {
      List<String> rules = filter.getRules();
      for (String s : rules) {
        if (!ruleMatch.isValidRule(s)) {
          throw new DassanaWorkflowValidationException(String.format("Sorry, the rule %s isn't valid", s));
        }
      }
    }

  }

}
