package app.dassana.core.restapi

import app.dassana.core.Helper
import app.dassana.core.launch.model.RunMode
import io.micronaut.context.annotation.Requires
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import org.json.JSONObject
import spock.lang.Specification
import spock.lang.Unroll

import javax.inject.Inject

@MicronautTest
@Requires(env = "test")
class RunTest extends Specification {


    @Inject
    Run run

    @Unroll
    void "alert-processing"() {
        when:
        input = Helper.getInputFromFile(input)
        def result = run.processAlert(new JSONObject(input),
                null,
                includeInputRequest,
                null,
                useCache).body()
        def observedResultJsonStr = new JSONObject(result).toString()
        def expectedJsonStr = new JSONObject(Helper.getInputFromFile(expected)).toString()

        then:
        observedResultJsonStr == expectedJsonStr

        where:
        input                              | expected                                               | useCache | includeInputRequest
//        "validJsonButNotAnAlert1.json"     | "validJsonButNotAnAlert1-response.json"                | true     | false
//        "validJsonButNotAnAlert2.json"     | "validJsonButNotAnAlert2-response.json"                | true     | false
//        "validJsonButNotAnAlert2.json"     | "validJsonButNotAnAlert2-response-with-input.json"     | true     | true
//        "validSecurityHubAlert.json"       | "validSecurityHubAlert-response.json"                  | true     | false
//        "validSecurityHubAlert.json"       | "validSecurityHubAlert-response-with-input.json"       | true     | true
//        "validAlertWithDraftWorkflow.json" | "validAlertWithDraftWorkflow-response.json"            | false    | false
//        "validAlertWithDraftWorkflow.json" | "validAlertWithDraftWorkflow-response.json"            | true     | false
//        "validAlertWithDraftWorkflow.json" | "validAlertWithDraftWorkflow-response-with-input.json" | false    | true
        "validAlertWithDraftWorkflow.json" | "validAlertWithDraftWorkflow-response-with-input.json" | true     | true
    }

    @Unroll
    void "run-workflow-directly"() {

        when:
        def processAlert = run.processAlert("{}", "foo", true, RunMode.TEST, true)

        then:
        processAlert.code() == 400

        when:
        def response = run.processAlert("{}", WorkflowsTest.FOO_NORMALIZER_ID, false, RunMode.TEST, false)


        then:
        response.code() == 200


    }


}
