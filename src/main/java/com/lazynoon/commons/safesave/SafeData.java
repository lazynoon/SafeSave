package com.lazynoon.commons.safesave;

import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 加密算法固定长度32字节
 *
 * @author Hansen
 * @date 2020-10-01
 */
abstract public class SafeData {
	/** 解密错误码 **/
	protected int errorCode = 0;
	/** 解密错误消息 **/
	protected String errorMessage = null;

	/** 加密算法主要版本号（固定1字节，从1开始，最多更新255个版本） **/
	protected int majorVersion = 0;
	/** 加密算法次要版本号（固定1字节，从0开始，最多更新256个版本） **/
	protected int minorVersion = 0;
	/** v1: 字节映射表ID（1字节，从1开始，最大容量255个） **/
	protected int byteMappingId = 0;
	/** v1: 密钥ID（3字节，从1开始，最大容量16777215个） **/
	protected int secretKeyId = 0;
	/** 保留字段（4字节） **/
	protected long reserved = 0;
	/** v1: 毫秒时间戳（6字节） **/
	protected long encryptTime = 0;
	/** v1: 随机数（4字节） **/
	protected long randomCode = 0;
	/** v1: 明文数据长度（4字节） **/
	protected int plaintextLength = 0;
	/** v1: 明文数据（最大支持2G） **/
	protected byte[] plaintextData = null;
	/** v1: 待加密数据签名（8字节，允许负数） **/
	protected long hashCode = 0;

	/**
	 * 以安静模式检查明文数据对象是否存在错误
	 *   通过错误码 getErrorCode() 检查是否存在错误
	 * @return 检查通过返回 true，否则返回 false
	 */
	abstract public boolean silentCheck();

	/**
	 * 计算全部字段，生成摘要
	 * @return 8字节long型数（包含负数）
	 */
	abstract public long generateHashCode();

	/**
	 * 合并加密用的头部数据（明文存储）
	 * @return 包含全部明文存储的字段
	 */
	abstract public byte[] mergeEncryptHead();

	/**
	 * 合并加密用的头部数据（密文存储的数据源）
	 * @return 包含全部密文存储的字段
	 */
	abstract public byte[] mergeEncryptBody();

	/**
	 * 检查版本是否符合要求
	 * @return 检查通过返回 true，否则返回 false
	 */
	protected boolean silentCheckFront() {
		errorCode = 0;
		if(majorVersion <= 0) {
			errorCode = 20100101;
			errorMessage = "majorVersion must greater than 0";
			return false;
		}
		if(majorVersion > 255) {
			errorCode = 20100102;
			errorMessage = "majorVersion must less than 256";
			return false;
		}
		if(minorVersion < 0) {
			errorCode = 20100103;
			errorMessage = "minorVersion must greater or equal to 0";
			return false;
		}
		if(minorVersion > 255) {
			errorCode = 20100104;
			errorMessage = "minorVersion must less than 256";
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		String str = "";
		if(errorCode != 0) {
			str += "errorCode: " + errorCode + ", errorMessage: " + errorMessage + "\n";
		}
		str += "version: " + majorVersion + "." + minorVersion
				+ ", byteMappingId: " + byteMappingId
				+ ", secretKeyId: " + secretKeyId
				+ ", plaintextLength: " + plaintextLength;
		if(encryptTime > 0) {
			str += ", encryptTime: ";
			str += (new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")).format(new Date(encryptTime));
		}
		return str;
	}

	/**
	 * 从加密机加载主次版本号
	 * @param encryptor 加密器
	 */
	protected void loadVersion(SafeEncryptor encryptor) {
		this.majorVersion = encryptor.majorVersion;
		this.minorVersion = encryptor.minorVersion;
	}

	/**
	 * 写入主次要版本号
	 * @param buff ByteBuffer对象
	 */
	protected void writeVersion(ByteBuffer buff) {
		buff.put((byte)majorVersion);
		buff.put((byte)minorVersion);
	}

	/**
	 * 设置明文数据对象的错误码与错误消息
	 * @param code 错误码
	 * @param message 错误消息
	 * @return 存在错误返回 false
	 */
	public boolean setDataError(int code, String message) {
		this.errorCode = code;
		this.errorMessage = message;
		return (code == 0);
	}

	/**
	 * 数据解密是否成功
	 *   与 “getErrorCode() == 0” 的结果相同
	 *   以安静模式解密，在使用数据前，需要先检查解密是否存在错误
	 * @return errorCode=0则返回true，否则返回false
	 */
	public boolean isDecryptSuccess() {
		return errorCode == 0;
	}

	/**
	 * 获取错误码
	 * @return 错误码（0表示无异常）
	 */
	public int getErrorCode() {
		return errorCode;
	}

	/**
	 * 获取错误消息
	 * @return 错误消息（错误码非0时有意义）
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * 获取主要版本号
	 * @return 主要版本号（有效值范围：1~255）
	 */
	public int getMajorVersion() {
		return majorVersion;
	}

	/**
	 * 获取次要版本号
	 * @return 主要版本号（有效值范围：1~255）
	 */
	public int getMinorVersion() {
		return minorVersion;
	}

	/**
	 * 获取设置次要版本号
	 * @param minorVersion 次要版本号（有效值范围：0~255）
	 */
	public void setMinorVersion(int minorVersion) {
		this.minorVersion = minorVersion;
	}

	/**
	 * 获取字节映射表ID
	 * @return 字节映射表ID
	 */
	public int getByteMappingId() {
		return byteMappingId;
	}

	/**
	 * 设置字节映射表ID
	 * @param byteMappingId 字节映射表ID
	 */
	public void setByteMappingId(int byteMappingId) {
		this.byteMappingId = byteMappingId;
	}

	/**
	 * 获取秘钥ID
	 * @return 秘钥ID
	 */
	public int getSecretKeyId() {
		return secretKeyId;
	}

	/**
	 * 设置秘钥ID
	 * @param secretKeyId 密钥ID
	 */
	public void setSecretKeyId(int secretKeyId) {
		this.secretKeyId = secretKeyId;
	}

	/**
	 * 获取保留字段信息
	 * @return 4字节的数字
	 */
	public long getReserved() {
		return reserved;
	}

	/**
	 * 设置保留字段信息
	 * @param reserved 4字节的数字
	 */
	public void setReserved(long reserved) {
		this.reserved = reserved;
	}

	/**
	 * 获取加密时间
	 * @return 加密时间（有效位，6字节）
	 */
	public long getEncryptTime() {
		return encryptTime;
	}

	/**
	 * 获取随机数
	 * @return 随机数（有效位，6字节）
	 */
	public long getRandomCode() {
		return randomCode;
	}

	/**
	 * 设置随机数
	 * @param randomCode 随机数（v1-,4字节有效）
	 */
	public void setRandomCode(long randomCode) {
		this.randomCode = randomCode;
	}

	/**
	 * 获取明文数据的长度
	 * @return 字节长度
	 */
	public int getPlaintextLength() {
		return plaintextLength;
	}

	/**
	 * 获取明文数据
	 * @return 字节数组，若数据不存在返回null
	 */
	public byte[] getPlaintextData() {
		return plaintextData;
	}

	/**
	 * 设置明文数据
	 * @param data 明文数据的字节数组
	 */
	public void setPlaintextData(byte[] data) {
		if(plaintextData != null) {
			this.plaintextLength = 0;
		} else {
			this.plaintextLength = data.length;
		}
		this.plaintextData = data;
	}

	/**
	 * 获取哈希摘要
	 * @return 包含负数在内的8字节long型数字
	 */
	public long getHashCode() {
		return hashCode;
	}

}
