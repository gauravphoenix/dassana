package app.dassana.core.launch.model;

import app.dassana.core.workflow.model.Workflow;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Request {

  private final String inputJson;
  boolean includeOriginalAlert=false;
  private Set<Workflow> workflowSetToRun;
  private Map<String,Workflow> workflowIdToWorkflowMap=new HashMap<>();
  private List<String> additionalWorkflowYamls;
  private String workflowId; //if specified, only this workflow will run
  private boolean useCache=false;

  public boolean isUseCache() {
    return useCache;
  }

  public void setUseCache(boolean useCache) {
    this.useCache = useCache;
  }

  public boolean isIncludeOriginalAlert() {
    return includeOriginalAlert;
  }

  public void setIncludeOriginalAlert(boolean includeOriginalAlert) {
    this.includeOriginalAlert = includeOriginalAlert;
  }


  public Map<String, Workflow> getWorkflowIdToWorkflowMap() {
    return workflowIdToWorkflowMap;
  }

  public void setWorkflowIdToWorkflowMap(
      Map<String, Workflow> workflowIdToWorkflowMap) {
    this.workflowIdToWorkflowMap = workflowIdToWorkflowMap;
  }



  public Request(String inputJson) {
    this.inputJson = inputJson;
  }

  public String getWorkflowId() {
    return workflowId;
  }

  public Set<Workflow> getWorkflowSetToRun() {
    return workflowSetToRun;
  }

  public void setWorkflowSetToRun(Set<Workflow> workflowSetToRun) {
    this.workflowSetToRun = workflowSetToRun;
  }

  public void setWorkflowId(String workflowId) {
    this.workflowId = workflowId;
  }

  public List<String> getAdditionalWorkflowYamls() {
    return additionalWorkflowYamls;
  }

  public void setAdditionalWorkflowYamls(List<String> additionalWorkflowYamls) {
    this.additionalWorkflowYamls = additionalWorkflowYamls;
  }



  public String getInputJson() {
    return inputJson;
  }

}
