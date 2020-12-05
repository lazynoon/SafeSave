package com.lazynoon.commons.safesave;

/**
 * 加密器
 *
 * @author Hansen
 * @date 2020-10-06
 */
abstract public class SafeEncryptor {
	/** 加密算法的最大版本号 **/
	public static final int MAX_VERSION = 255;
	/** 加密算法主要版本号 **/
	protected int majorVersion = 0;
	/** 加密算法次要版本号 **/
	protected int minorVersion = 0;

	protected SafeKeyStore keyStore = null;

	protected SafeEncryptor() {}

	/**
	 * 初始化加密器（构建加密器对象后，必调用）
	 * @param majorVersion 主要版本号
	 * @param minorVersion 次要版本号
	 * @param keyStore 秘钥存储器
	 */
	protected void init(int majorVersion, int minorVersion, SafeKeyStore keyStore) {
		if(majorVersion < 1) {
			throw new IllegalArgumentException("Encryptor major version is less than " + 1);
		}
		if(majorVersion > MAX_VERSION) {
			throw new IllegalArgumentException("Encryptor major version is greater than " + MAX_VERSION);
		}
		if(minorVersion < 0) {
			throw new IllegalArgumentException("Encryptor minor version is less than " + 0);
		}
		if(minorVersion > MAX_VERSION) {
			throw new IllegalArgumentException("Encryptor minor version is greater than " + MAX_VERSION);
		}
		if(keyStore == null) {
			throw new IllegalArgumentException("keyStore is null");
		}
		this.majorVersion = majorVersion;
		this.minorVersion = minorVersion;
		this.keyStore = keyStore;
	}

	/** 获取加密器定义的主要版本号 **/
	abstract public int getClassMajorVersion();

	/** 安静模式检查加解密对象是否存在错误（不抛出检查异常） **/
	protected boolean silentCheckData(SafeData safeData) {
		if(safeData.silentCheck() == false) {
			return false;
		}
		if(safeData.majorVersion != getClassMajorVersion()) {
			safeData.errorCode = 20100911;
			safeData.errorMessage = "majorVersion is not equal. ";
			return false;
		}
		if(keyStore == null) {
			safeData.errorCode = 20100912;
			safeData.errorMessage = "keyStore is null";
		}
		return true;
	}

	/**
	 * 加密字节数组
	 * @param data 明文数据
	 * @param keyId 秘钥ID
	 * @param mappingId 字节映射表ID
	 * @return 密文数据
	 * @throws SafeCryptoException 加密异常
	 */
	abstract public byte[] encrypt(byte[] data, int keyId, int mappingId) throws SafeCryptoException;

	/**
	 * 明文数据对象，直接加密
	 * @param data 明文数据对象
	 * @return 密文数据
	 * @throws SafeCryptoException 加密异常
	 */
	abstract public byte[] encrypt(SafeData data) throws SafeCryptoException;

	/**
	 * 密文数据解密
	 * @param data 密文数据
	 * @return 明文数据对象
	 * @throws SafeCryptoException 解密异常
	 */
	public SafeData decrypt(byte[] data) throws SafeCryptoException {
		SafeData safeData = silentDecrypt(data);
		if(safeData == null) {
			throw new SafeCryptoException(20100201, "decrypt result is null");
		}
		if(safeData.isDecryptSuccess() == false) {
			throw new SafeCryptoException(20100202, "decrypt error - " + safeData.errorMessage);
		}
		return safeData;
	}

	/**
	 * 以安静模式解密（不抛出解密异常。是否解密成功，通过检查返回值实现）
	 * @param data 密文数据
	 * @return 加密版本号识别不了，返回 null。非空值，须先检查解密是否成功
	 */
	abstract public SafeData silentDecrypt(byte[] data);

	/**
	 * 加密字节数组
	 * @param data 明文数据
	 * @param keyId 秘钥ID
	 * @return 密文数据
	 * @throws SafeCryptoException 加密异常
	 */
	public byte[] encrypt(byte[] data, int keyId) throws SafeCryptoException {
		return encrypt(data, keyId, 0);
	}

	/**
	 * 获取主要版本号
	 * @return 主要版本号，正常的值范围（1~255）
	 */
	public int getMajorVersion() {
		return majorVersion;
	}

	/**
	 * 获取次要版本号
	 * @return 次要版本号，正常的值范围（0~255）
	 */
	public int getMinorVersion() {
		return minorVersion;
	}

	/**
	 * 按秘钥ID，获取秘钥
	 * @param keyId 秘钥ID
	 * @return 秘钥字节数组
	 */
	protected byte[] getSecretKey(int keyId) {
		if(keyStore == null) {
			return null;
		}
		return keyStore.secretKeyIdMap.get(keyId);
	}

	/**
	 * 获取加密用的字节映射
	 * @param mappingId 字节映射ID
	 * @return 字节映射数组
	 */
	protected byte[] getEncryptByteMapping(int mappingId) {
		if(keyStore == null) {
			return null;
		}
		return keyStore.byteMappingIdForEncrypt.get(mappingId);
	}

	/**
	 * 获取解密用的字节映射
	 * @param mappingId 字节映射ID
	 * @return 字节映射数组
	 */
	protected byte[] getDecryptByteMapping(int mappingId) {
		if(keyStore == null) {
			return null;
		}
		return keyStore.byteMappingIdForDecrypt.get(mappingId);
	}


}
