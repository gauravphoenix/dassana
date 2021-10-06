package app.dassana.core.contentmanager;

import app.dassana.core.launch.model.Request;
import app.dassana.core.util.StringyThings;
import app.dassana.core.workflow.model.Workflow;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import javax.inject.Singleton;
import org.apache.commons.io.FileUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class ContentManager implements ContentManagerApi {

  private static final int SYNC_INTERVAL_IN_SECONDS = 30;

  private final RemoteContentDownloadApi contentDownloader;

  private final Parser parser;

  private final Set<Workflow> defaultWorkflowSet = ConcurrentHashMap.newKeySet();
  private final Set<CustomWorkflow> customWorkFlowSet = ConcurrentHashMap.newKeySet();


  private long localLastUpdated = 0L;

  public static final String VENDOR_ID = "vendor-id";
  public static final String POLICY_CONTEXT = "policy-context";
  public static final String POLICY_CONTEXT_CLASS = "class";
  public static final String POLICY_CONTEXT_SUBCLASS = "subclass";
  public static final String POLICY_CONTEXT_CAT = "category";
  public static final String POLICY_CONTEXT_SUB_CAT = "subcategory";
  public static final String POLICY_CONTEXT_FILTERS = "filters";
  public static final String GENERAL_CONTEXT = "general-context";
  public static final String RESOURCE_CONTEXT = "resource-context";
  public static final String RESOURCE_CONTEXT_CSP = "csp";
  public static final String RESOURCE_CONTEXT_SERVICE = "service";
  public static final String RESOURCE_CONTEXT_TYPE = "resource-type";

  public static final String NORMALIZE = "normalize";
  public static final String WORKFLOW_ID = "workflowId";

  public enum FIELDS {
    RISK("risk"),
    CLASS("class"),
    SUB_CLASS("subclass"),
    CATEGORY("category"),
    SUB_CATEGORY("subcategory"),
    STEPS("steps"),
    USES("uses"),
    CSP("csp"),
    SERVICE("service"),
    TYPE("type"),
    OUTPUT("output"),
    VENDOR_ID("vendor-id"),
    RESOURCE_TYPE("resource-type");

    private final String name;

    FIELDS(final String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    @Override
    public String toString() {
      return name;
    }
  }


  private static final Logger logger = LoggerFactory.getLogger(ContentManager.class);


  public ContentManager(RemoteContentDownloadApi contentDownloader,
      Parser parser) throws IOException {

    this.contentDownloader = contentDownloader;
    this.parser = parser;

    processEmbeddedContent();
  }

  void processEmbeddedContent() throws IOException {
    String embeddedContentPath;
    try {
      embeddedContentPath = Thread.currentThread().getContextClassLoader().getResource("content/workflows/").getFile();
    } catch (NullPointerException e) {
      throw new IllegalArgumentException("Unable to read embedded content, make sure to run mvn clean "
          + "process-resources first if you are running it locally ");
    }
    defaultWorkflowSet.addAll(processDir(new File(embeddedContentPath)));

  }

  public Set<Workflow> getDefaultWorkflowSet() {
    return defaultWorkflowSet;
  }

  private Set<Workflow> processDir(File dir) throws IOException {

    Stream<Path> walk = Files.walk(Paths.get(dir.toURI()));
    Set<Workflow> workflowSet = new HashSet<>();

    walk.filter(Files::isRegularFile).forEach(path -> {
      File file = path.toFile();
      try {
        String readFileToString = FileUtils.readFileToString(file, Charset.defaultCharset());
        String jsonFromYaml = StringyThings.getJsonFromYaml(readFileToString);
        Workflow workflow = parser.getWorkflow(new JSONObject(jsonFromYaml));
        workflow.setDefault(true);
        workflow.setWorkflowFileContent(readFileToString);
        workflowSet.add(workflow);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });

    return workflowSet;
  }


  private void updateCustomWorkflows(Request request) throws Exception {
    Long remoteLastUpdated = contentDownloader.getLastUpdated(request.isUseCache());

    if (remoteLastUpdated > localLastUpdated) {
      customWorkFlowSet.clear();
      List<String> customWorkflows = contentDownloader.downloadContent();
      localLastUpdated = System.currentTimeMillis();
      for (String s : customWorkflows) {
        Workflow workflow = parser.getWorkflow(new JSONObject(StringyThings.getJsonFromYaml(s)));
        workflow.setDefault(false);
        workflow.setWorkflowFileContent(s);
        customWorkFlowSet.add(new CustomWorkflow(workflow, s));
      }
    }

  }

  public Set<CustomWorkflow> getCustomWorkFlowSet(Request request) throws Exception {
    updateCustomWorkflows(request);
    return customWorkFlowSet;
  }


  @Override
  public Set<Workflow> getWorkflowSet(Request request) throws Exception {

    updateCustomWorkflows(
        request);//it may sound like we have a race condition here, but we don't. Lambda functions follow
    // per-request model so if one lambda function is busy processing a request, the next request won't hit it, it
    // will go to a new lambda function

    Set<Workflow> workingSet = new HashSet<>(defaultWorkflowSet);

    for (CustomWorkflow customWorkflow : customWorkFlowSet) {
      workingSet.remove(customWorkflow.getWorkflow());
      workingSet.add(customWorkflow.getWorkflow());
    }

    //if the additional workflows are provided,we use them. This is for the editor.dassana.io use case where we are
    // editing workflows - this occurs when workflow is in draft mode, i.e. modified but not saved
    if (request != null && request.getAdditionalWorkflowYamls() != null
        && request.getAdditionalWorkflowYamls().size() > 0) {

      List<String> additionalWorkflowYamls = request.getAdditionalWorkflowYamls();
      //we want to run only the workflow provided, so we clone the workflowSet and add it
      Set<Workflow> workflowSetToUse = new HashSet<>(workingSet);
      for (String workflowYamlStr : additionalWorkflowYamls) {
        String jsonFromYaml = StringyThings.getJsonFromYaml(workflowYamlStr);
        Workflow workflow = parser.getWorkflow(new JSONObject(jsonFromYaml));
        workflow.setDefault(false);
        workflow.setWorkflowFileContent(workflowYamlStr);
        workflowSetToUse.remove(workflow);
        workflowSetToUse.add(workflow);
      }
      return workflowSetToUse;
    }

    return workingSet;
  }
}
