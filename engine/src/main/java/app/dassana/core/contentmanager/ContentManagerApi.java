package app.dassana.core.contentmanager;

import app.dassana.core.launch.model.Request;
import app.dassana.core.workflow.model.Workflow;
import java.util.Set;

public interface ContentManagerApi {

  Set<Workflow> getWorkflowSet(Request request) throws Exception;

}
