package com.lazynoon.commons.safesave.impl.v01;

import com.lazynoon.commons.safesave.SafeData;
import com.lazynoon.commons.safesave.SafeEncryptor;
import com.lazynoon.commons.safesave.utils.SafeMathUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * v1.0 数据格式
 * ----- 明文存储（长度：6B） -----
 *  1B majorVersion 加密算法主要版本号
 *  1B minorVersion 加密算法次要版本号
 *  1B mappingId 字节映射表ID（从1开始，最大容量255个）
 *  3B keyId 密钥ID（从1开始，最大容量16777215个）
 * ----- 加密存储（长度：28B + length） -----
 *  4B reserved 保留字段
 *  6B encryptTime 毫秒时间戳
 *  4B randomCode 随机数
 *  4B plaintextLength 明文数据长度
 *  ?B plaintextData 明文数据（可变长度，最少1B，最大2GB）
 *  8B hashCode 数据签名
 *
 * @author Hansen
 * @date 2020-11-01
 */
public class v01SafeData extends SafeData {
	/** 字节序（高字节在前） **/
	public static final ByteOrder ENDIAN = ByteOrder.BIG_ENDIAN;
	public static final int PLAINTEXT_HEAD_LENGTH = 6;
	public static final int TOTAL_HEAD_LENGTH = 32;


	private static final long MASK_6_BYTE = 0xFFFFFFFFFFFFL;
	private static final long MASK_4_BYTE = 0xFFFFFFFFL;
	private static final long MASK_2_BYTE = 0xFFFFL;
	private static final long MASK_1_BYTE = 0xFFL;

	private v01SafeData() {}

	static v01SafeData newInstance(SafeEncryptor encryptor) {
		v01SafeData safeData = new v01SafeData();
		safeData.majorVersion = encryptor.getMajorVersion();
		safeData.minorVersion = encryptor.getMinorVersion();
		return safeData;
	}

	public static v01SafeData newInstance(SafeEncryptor encryptor, byte[] data, int keyId, int mappingId) {
		v01SafeData safeData = new v01SafeData();
		safeData.loadVersion(encryptor);
		safeData.byteMappingId = mappingId;
		safeData.secretKeyId = keyId;
		safeData.randomCode = Math.round(Math.random() * 0x1FFFFFFFFL);
		safeData.randomCode &= MASK_4_BYTE;
		if(data != null) {
			safeData.plaintextLength = data.length;
		}
		safeData.plaintextData = data;
		safeData.encryptTime = System.currentTimeMillis();
		safeData.encryptTime &= MASK_6_BYTE;
		safeData.hashCode = safeData.generateHashCode();
		return safeData;
	}

	@Override
	public boolean silentCheck() {
		if(super.silentCheckFront() == false) {
			return false;
		}
		if(byteMappingId < 0 && byteMappingId > 0xFF) {
			errorCode = 20101101;
			errorMessage = "mappingId not in valid scope";
			return false;
		} else if(secretKeyId <= 0 && secretKeyId > 0xFFFFFF) {
			errorCode = 20101102;
			errorMessage = "keyId not in valid scope";
			return false;
		} else if(encryptTime <= 0L && encryptTime > MASK_6_BYTE) {
			errorCode = 20101103;
			errorMessage = "encryptTime not in valid scope";
			return false;
		} else if(randomCode < 0L && randomCode > MASK_4_BYTE) {
			errorCode = 20101104;
			errorMessage = "randomCode not in valid scope";
			return false;
		} else if(reserved != 0) {
			errorCode = 20101105;
			errorMessage = "reserved is not 0";
			return false;
		} else if(reserved != 0) {
			errorCode = 20101105;
			errorMessage = "reserved is not 0";
			return false;
		} else if(plaintextData == null || plaintextData.length == 0) {
			errorCode = 20101106;
			errorMessage = "plaintext is empty";
			return false;
		} else if(plaintextLength != plaintextData.length) {
			errorCode = 20101107;
			errorMessage = "data length is not equal";
			return false;
		}

		return true;
	}

	/**
	 * 合并加密用的头部数据（明文存储）
	 * @return 包含全部明文存储的字段
	 */
	@Override
	public byte[] mergeEncryptHead() {
		byte[] bts = new byte[6];
		ByteBuffer buff = ByteBuffer.wrap(bts);
		buff.order(ENDIAN);
		writeVersion(buff); //主次版本号，2字节
		buff.put((byte) byteMappingId);
		buff.put((byte) (byteMappingId >>> 16));
		buff.putShort((short) (byteMappingId & MASK_2_BYTE));
		return bts;
	}

	/**
	 * 合并加密用的头部数据（密文存储的数据源）
	 * @return 包含全部密文存储的字段
	 */
	@Override
	public byte[] mergeEncryptBody() {
		byte[] bts = new byte[26 + plaintextLength];
		ByteBuffer buff = ByteBuffer.wrap(bts);
		buff.order(ENDIAN);
		buff.putInt((int)reserved);
		buff.putShort((short) (encryptTime >>> 32));
		buff.putInt((int) (encryptTime & MASK_4_BYTE));
		buff.putInt((int) randomCode);
		buff.putInt(plaintextLength);
		buff.put(plaintextData);
		buff.putLong(hashCode);
		//校验字节数组末尾的数据签名（hashCode）
		long signedCode = SafeMathUtils.parseLongAsBigEndian(bts, bts.length - 8, 8);
		if(hashCode != signedCode) {
			throw new RuntimeException("[SafeData] plaintext byte array merge error.");
		}
		return bts;
	}

	/**
	 * 计算全部字段，生成摘要
	 * @return 8字节long型数（包含负数）
	 */
	@Override
	public long generateHashCode() {
		long code = 0;
		code ^= ((long)majorVersion) << 56;
		code ^= ((long)minorVersion) << 48;
		code ^= ((long)byteMappingId) << 32;
		code ^= ((long)secretKeyId) << 16;
		code ^= reserved;
		code ^= encryptTime;
		code ^= randomCode << 32;
		code ^= randomCode;
		code ^= plaintextLength;
		if(plaintextData != null) {
			int k = 0;
			for(byte b : plaintextData) {
				long num = ((long) b) & 0xFF;
				if(k >= 64) {
					k = 0;
				}
				if(k > 0) {
					num <<= k;
				}
				k += 8;
				code ^= num;
			}
		}
		return code;
	}

	protected boolean loadEncryptedHead(byte[] data) {
		int theMajorVersion = SafeMathUtils.parseIntAsBigEndian(data, 0, 1);
		int theMinorVersion = SafeMathUtils.parseIntAsBigEndian(data, 1, 1);
		this.byteMappingId = SafeMathUtils.parseIntAsBigEndian(data, 2, 1);
		this.secretKeyId = SafeMathUtils.parseIntAsBigEndian(data, 3, 3);
		if(theMajorVersion != this.majorVersion || theMinorVersion != this.minorVersion) {
			this.errorCode = 20101131;
			this.errorMessage = "SafeData version and data version is not equal";
		}
		return (this.errorCode == 0);
	}

	protected boolean loadDecryptedBody(byte[] bodyBts) {
		try {
			reserved = SafeMathUtils.parseIntAsBigEndian(bodyBts, 0, 4);
			encryptTime = SafeMathUtils.parseLongAsBigEndian(bodyBts, 4, 6);
			randomCode = SafeMathUtils.parseLongAsBigEndian(bodyBts, 10, 4);
			plaintextLength = SafeMathUtils.parseIntAsBigEndian(bodyBts, 14, 4);
			if(plaintextLength > bodyBts.length) {
				return setDataError(20101135, "plaintextLength is greater than plaintextData length");
			}
			plaintextData = new byte[plaintextLength];
			System.arraycopy(bodyBts, 18, plaintextData, 0, plaintextLength);
			hashCode = SafeMathUtils.parseLongAsBigEndian(bodyBts, 18 + plaintextLength, 8);
		} catch(IndexOutOfBoundsException e) {
			return setDataError(20101136, "IndexOutOfBoundsException");
		}
		return (this.errorCode == 0);
	}

}
