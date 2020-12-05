package com.lazynoon.commons.safesave;

/**
 * 安全存储异常（含错误码）
 *
 * @author Hansen
 * @date 2020-10-18
 */
public class SafeCryptoException extends Exception {
	private final int code;

	public SafeCryptoException(int code, String message) {
		super(message);
		this.code = code;
	}

	public int getCode() {
		return code;
	}

}
