package app.dassana.core.restapi

import app.dassana.core.Helper
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import org.json.JSONObject
import spock.lang.Specification
import spock.lang.Unroll

import javax.inject.Inject

@MicronautTest
class RunTest extends Specification {


    @Inject
    Run run;

    @Unroll
    void "alert-processing"() {

        when:
        input = Helper.getInputFromFile(input)
        def result = run.processAlert(new JSONObject(input), null, true, null).body()
        def observedResultJsonStr = new JSONObject(result).toString()
        def expectedJsonStr = new JSONObject(Helper.getInputFromFile(expected)).toString()

        then:
        observedResultJsonStr == expectedJsonStr

        where:
        input                              | expected
        "validJsonButNotAnAlert1.json"     | "validJsonButNotAnAlert1-response.json"
        "validJsonButNotAnAlert2.json"     | "validJsonButNotAnAlert2-response.json"
        "validSecurityHubAlert.json"       | "validSecurityHubAlert-response.json"
        "validAlertWithDraftWorkflow.json" | "validAlertWithDraftWorkflow-response.json"

    }
}
