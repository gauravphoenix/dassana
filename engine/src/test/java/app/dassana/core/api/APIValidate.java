/*
package app.dassana.core.api;

import app.dassana.core.api.linter.*;
import app.dassana.core.contentmanager.ContentManager;
import app.dassana.core.launch.model.Message;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

@MicronautTest
public class APIValidate {

	@Inject
	Helper helper;

	@Test
	public void validateNormalizeLinter(){
		NormalizeLinter normalizeLinter = new NormalizeLinter();
		try {
			normalizeLinter.init();
			String json = helper.getFileContent("inputs/validVendor.json");
			List<Message> messages = normalizeLinter.validate(json);
			if(messages.size() > 0){
				Assertions.fail(messages.toString());
			}
		}catch (Exception e){
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	public void validateGeneralLinter(){
		GeneralLinter generalLinter = new GeneralLinter();
		try {
			generalLinter.init();
			String json = helper.getFileContent("inputs/validPolicy.json");
			List<Message> messages = generalLinter.validate(json);
			if(messages.size() > 0){
				Assertions.fail(messages.toString());
			}
		}catch (Exception e){
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	public void validateResourceLinter(){
		ResourceLinter resourceLinter = new ResourceLinter();
		try {
			resourceLinter.init();
			String json = helper.getFileContent("inputs/validPolicy.json");
			List<Message> messages = resourceLinter.validate(json);
			if(messages.size() > 0){
				Assertions.fail(messages.toString());
			}
		}catch (Exception e){
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	public void validatePolicyLinter(){
		PolicyLinter policyLinter = new PolicyLinter();
		try {
			policyLinter.init();
			String json = helper.getFileContent("inputs/validPolicy.json");
			List<Message> messages = policyLinter.validate(json);
			if(messages.size() > 0){
				Assertions.fail(messages.toString());
			}
		}catch (Exception e){
			Assertions.fail(e.getMessage());
		}
	}

	//@Test
	public void testValidator() throws IOException {
		String json = helper.getFileContent("inputs/validPolicy.json");
		ContextValidator validator = new ContextValidator();
		String issues = validator.validate(json, ContentManager.POLICY_CONTEXT);
		if(issues != null){
			Assertions.fail(issues);
		}
	}

	@Test
	public void parse(){
		String text = "org.json.JSONException: JSONObject[\"csp\"] not found.";
		String field = StringUtils.substringsBetween(text , "\"", "\"")[0];
		String errMsg = String.format("Missing required fields: %s", field);
		int x = 0;
	}

}
*/
