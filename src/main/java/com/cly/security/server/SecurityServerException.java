package com.cly.security.server;

public class SecurityServerException extends Exception {

	/**
	 * 
	 */
	private String errCode;
	private String errMsg;
	private static final long serialVersionUID = 1L;

	public SecurityServerException(Exception e, String errCode, String errMsg) {
		super(e);
		init(errCode, errMsg);
	}

	private void init(String errCode, String errMsg) {

		this.errCode = errCode;
		this.errMsg = errMsg;

	}

	public SecurityServerException(String errCode, String errMsg) {
		init(errCode, errMsg);
	}

	public String getErrCode() {
		return errCode;
	}

	@Override
	public String getMessage() {
		return errMsg;
	}

}
