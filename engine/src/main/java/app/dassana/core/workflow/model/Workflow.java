package app.dassana.core.workflow.model;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class Workflow {

  private Integer schema;
  private String type;
  private String id = "";
  private String name = "";
  List<String> labels = new LinkedList<>();
  List<Filter> filters = new LinkedList<>();
  private List<Step> steps = new LinkedList<>();
  private List<Output> output = new LinkedList<>();

  boolean isDefault = true;
  String workflowFileContent;

  public String getWorkflowFileContent() {
    return workflowFileContent;
  }

  public void setWorkflowFileContent(String workflowFileContent) {
    this.workflowFileContent = workflowFileContent;
  }

  public boolean isDefault() {
    return isDefault;
  }

  public void setDefault(boolean aDefault) {
    isDefault = aDefault;
  }

  public Integer getSchema() {
    return schema;
  }

  public void setSchema(Integer schema) {
    this.schema = schema;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }


  public List<String> getLabels() {
    return labels;
  }

  public void setLabels(List<String> labels) {
    this.labels = labels;
  }

  public List<Filter> getFilters() {
    return filters;
  }

  public void setFilters(List<Filter> filters) {
    this.filters = filters;
  }

  public List<Output> getOutput() {
    return output;
  }

  public void setOutput(List<Output> output) {
    this.output = output;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public List<Step> getSteps() {
    return steps;
  }

  public void setSteps(List<Step> steps) {
    this.steps = steps;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Workflow workflow = (Workflow) o;
    return Objects.equals(id, workflow.id);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id);
  }
}
