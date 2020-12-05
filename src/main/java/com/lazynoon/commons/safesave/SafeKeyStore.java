package com.lazynoon.commons.safesave;

import java.util.LinkedHashMap;

/**
 * 密钥与字节映射表存储器
 *
 * @author Hansen
 * @date 2020-10-31
 */
public class SafeKeyStore {
	protected LinkedHashMap<Integer, byte[]> secretKeyIdMap = new LinkedHashMap<Integer, byte[]>();
	protected LinkedHashMap<Integer, byte[]> byteMappingIdForEncrypt = new LinkedHashMap<Integer, byte[]>();
	protected LinkedHashMap<Integer, byte[]> byteMappingIdForDecrypt = new LinkedHashMap<Integer, byte[]>();

	public SafeKeyStore registerSecretKey(int keyId, byte[] secretKey) {
		if(keyId <= 0) {
			throw new IllegalArgumentException("safe keyId must greater than 0");
		}
		if(secretKey == null || secretKey.length == 0) {
			throw new IllegalArgumentException("safe secretKey is empty");
		}
		secretKeyIdMap.put(keyId, secretKey);
		return this;
	}

	public SafeKeyStore registerByteMapping(int mappingId, byte[] byteMapping) {
		if (mappingId <= 0) {
			throw new IllegalArgumentException("safe mappingId must greater than 0");
		}
		if (byteMapping == null || byteMapping.length == 0) {
			throw new IllegalArgumentException("safe keyMapping is empty");
		}
		if (byteMapping.length != 256) {
			throw new IllegalArgumentException("safe keyMapping length is not 256");
		}
		byte[] reverseByteMapping = new byte[256];
		for (int i = 0; i < reverseByteMapping.length; i++) {
			reverseByteMapping[i] = 0;
		}
		int zeroIndex = ((int) byteMapping[0]) & 0xFF;
		for (int i = 1; i < byteMapping.length; i++) {
			int reverseIndex = ((int) byteMapping[i]) & 0xFF;
			if (reverseIndex == zeroIndex || reverseByteMapping[reverseIndex] != 0) {
				throw new IllegalArgumentException("safe keyMapping index is not unique");
			}
			reverseByteMapping[reverseIndex] = (byte) i;
		}
		byteMappingIdForEncrypt.put(mappingId, byteMapping);
		byteMappingIdForDecrypt.put(mappingId, reverseByteMapping);
		return this;
	}
}
