package com.lazynoon.commons.safesave.impl.v01;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.SafeData;
import com.lazynoon.commons.safesave.SafeEncryptor;
import com.lazynoon.commons.safesave.utils.SafeByteUtils;
import net_io.myaction.tool.crypto.AES;
import net_io.myaction.tool.exception.CryptoException;

/**
 * v1.0 加密解密处理类
 *
 * @author Hansen
 * @date 2020-11-21
 */
public class v01SafeEncryptor extends SafeEncryptor {
	public static final int MAJOR_VERSION = 1;

	public v01SafeEncryptor() {}

	@Override
	public int getClassMajorVersion() {
		return MAJOR_VERSION;
	}

	@Override
	public byte[] encrypt(byte[] data, int keyId, int mappingId) throws SafeCryptoException {
		return encrypt(v01SafeData.newInstance(this, data, keyId, mappingId));
	}

	@Override
	public byte[] encrypt(SafeData data) throws SafeCryptoException {
		if(data == null) {
			return null;
		}
		if(silentCheckData(data) == false) {
			throw new SafeCryptoException(data.getErrorCode(), data.getErrorMessage());
		}
		byte[] key = getSecretKey(data.getSecretKeyId());
		if(key == null) {
			throw new SafeCryptoException(20101501, "Key not found. keyId is "+data.getSecretKeyId());
		}
		byte[] byteMapping = null;
		if(data.getByteMappingId() != 0) {
			byteMapping = getEncryptByteMapping(data.getByteMappingId());
			if(byteMapping == null) {
				throw new SafeCryptoException(20101502, "Byte Mapping not found. mappingId is "+data.getByteMappingId());
			}
		}
		byte[] headBts = data.mergeEncryptHead();
		byte[] bodyBts = data.mergeEncryptBody();
		AES aes = new AES(key);
		try {
			bodyBts = aes.encrypt(bodyBts);
		} catch (CryptoException e) {
			throw new SafeCryptoException(20101503, e.getMessage());
		}
		if(byteMapping != null) {
			bodyBts = SafeByteUtils.convertMapping(bodyBts, byteMapping);
		}
		byte[] result = new byte[headBts.length + bodyBts.length];
		System.arraycopy(headBts, 0, result, 0, headBts.length);
		System.arraycopy(bodyBts, 0, result, headBts.length, bodyBts.length);
		return result;
	}

	@Override
	public SafeData silentDecrypt(byte[] data) {
		v01SafeData safeData = v01SafeData.newInstance(this);
		if(data == null || data.length < v01SafeData.TOTAL_HEAD_LENGTH) {
			safeData.setDataError(20101601, "Encrypted Data length is less than " + 32);
			return safeData;
		}
		if(safeData.loadEncryptedHead(data) == false) {
			return safeData;
		}
		byte[] key = getSecretKey(safeData.getSecretKeyId());
		if(key == null) {
			safeData.setDataError(20101602, "Key not found. keyId is "+safeData.getSecretKeyId());
			return safeData;
		}
		byte[] byteMapping = null;
		if(safeData.getByteMappingId() != 0) {
			byteMapping = getDecryptByteMapping(safeData.getByteMappingId());
			if(byteMapping == null) {
				safeData.setDataError(20101603, "Byte Mapping not found. mappingId is "+safeData.getByteMappingId());
				return safeData;
			}
		}
		byte[] bodyBts = new byte[data.length-v01SafeData.PLAINTEXT_HEAD_LENGTH];
		System.arraycopy(data, v01SafeData.PLAINTEXT_HEAD_LENGTH, bodyBts, 0, bodyBts.length);
		if(byteMapping != null) {
			bodyBts = SafeByteUtils.convertMapping(bodyBts, byteMapping);
		}
		AES aes = new AES(key);
		try {
			bodyBts = aes.decrypt(bodyBts);
		} catch (CryptoException e) {
			safeData.setDataError(20101604, "CryptoException: "+e.getMessage());
			return safeData;
		}
		if(safeData.loadDecryptedBody(bodyBts) == false) {
			return safeData;
		}
		safeData.silentCheck();
		return safeData;
	}
}
