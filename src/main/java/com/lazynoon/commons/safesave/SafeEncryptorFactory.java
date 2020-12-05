package com.lazynoon.commons.safesave;

import com.lazynoon.commons.safesave.impl.v01.v01SafeEncryptor;

/**
 * 加密机工厂

 * @author Hansen
 * @date 2020-10-18
 */
public class SafeEncryptorFactory {

	private static Class<?>[] encryptorPool = new Class<?>[256];

	static {
		for(int i=0; i<encryptorPool.length; i++) {
			encryptorPool[i] = null;
		}
		encryptorPool[v01SafeEncryptor.MAJOR_VERSION] = v01SafeEncryptor.class;
	}

	public static SafeEncryptor getInstance(int majorVersion, int minorVersion, SafeKeyStore keyStore) {
		if(majorVersion < 0 && majorVersion >= encryptorPool.length) {
			return null;
		}
		Class<?> cls = encryptorPool[majorVersion];
		if(cls == null) {
			return null;
		}
		//SafeEncryptor的子类
		Class<SafeEncryptor> encryptorClass =  (Class<SafeEncryptor>) cls;
		SafeEncryptor encryptor;
		try {
			encryptor = encryptorClass.newInstance();
		} catch (InstantiationException e) {
			throw new RuntimeException("[InstantiationException] "+e.getMessage());
		} catch (IllegalAccessException e) {
			throw new RuntimeException("[IllegalAccessException] "+e.getMessage());
		}
		encryptor.init(majorVersion, minorVersion, keyStore);
		return encryptor;
	}

	public static int getMajorVersion(byte[] encryptedData) {
		if(encryptedData == null || encryptedData.length < 2) {
			return 0;
		}
		return encryptedData[0] & 0xFF;
	}

	public static int getMinorVersion(byte[] encryptedData) {
		if(encryptedData == null || encryptedData.length < 2) {
			return 0;
		}
		return encryptedData[1] & 0xFF;
	}


}
