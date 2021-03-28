package com.lazynoon.commons.safesave;

/**
 * 安全存储异常（含错误码）
 *
 * @author Hansen
 * @date 2020-10-18
 */
public class SafeCryptoException extends Exception {
	private final int code;
	private Exception causeException = null;

	public SafeCryptoException(int code, String message) {
		super(message);
		this.code = code;
	}

	public SafeCryptoException(Exception causeException) {
		this.code = -1;
		this.causeException = causeException;
	}

	public int getCode() {
		return code;
	}

	@Override
	public String getMessage() {
		if(causeException != null) {
			return causeException.toString();
		} else {
			return super.getMessage();
		}

	}

}

