package app.dassana.core.api.linter;

import com.google.gson.Gson;

public class StatusMsg {

	private boolean isError;
	private String msg;
	private Gson gson = new Gson();

	public StatusMsg(boolean isError){
		this.isError = isError;
	}

	public StatusMsg(boolean isError, String field) {
		this.isError = isError;
		this.msg = field;
	}

	public boolean isError() {
		return isError;
	}

	public void setError(boolean error) {
		isError = error;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	@Override
	public String toString() {
		return "StatusMsg{" +
						"isError=" + isError +
						", msg='" + msg + '\'' +
						'}';
	}
}