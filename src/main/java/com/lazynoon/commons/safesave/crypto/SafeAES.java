package com.lazynoon.commons.safesave.crypto;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.utils.SafeEncodeUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SafeAES {

	/** 默认的加密算法 **/
	public static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

	/** 密钥转换算法 **/
	public static enum KeyAlgorithm {
		/** 直接使用输入密钥（密钥超长则截取，位数不足则截取） **/
		PLAIN,
		/** 基于SHA1哈希算法的密钥转换 **/
		SHA1PRNG
	}
	/** 加密算法名称 **/
	private static final String KEY_ALGORITHM = "AES";
	/** 最小密钥长度 **/
	private int MIN_KEY_SIZE = 64;
	/** 密钥长度 **/
	private int maxKeySize = 128;
	/** 加密算法 **/
	private String cipherAlgorithm = DEFAULT_CIPHER_ALGORITHM;
	/** 密钥转换算法 **/
	private KeyAlgorithm keyAlgorithm = KeyAlgorithm.PLAIN;

	/** 密钥 **/
	private byte[] secretKey;

	/**
	 *
	 * @param password 加密密码（按UTF-8编码取值）
	 */
	public SafeAES(String password) {
		this.secretKey = password.getBytes(SafeEncodeUtils.Charsets.UTF_8);
	}

	public SafeAES(byte[] secretKey) {
		this.secretKey = secretKey;
	}

	public SafeAES(byte[] secretKey, String algorithm) throws SafeCryptoException {
		this.secretKey = secretKey;
		this.setCipherAlgorithm(algorithm);
	}

	/**
	 * AES 加密操作
	 *
	 * @param str 待加密内容
	 * @return 返回Base64转码后的加密数据
	 * @throws SafeCryptoException 加密异常
	 */
	public String encrypt(String str) throws SafeCryptoException {
		byte[] bts = str.getBytes(SafeEncodeUtils.Charsets.UTF_8);
		bts = encrypt(bts);
		return SafeEncodeUtils.base64Encode(bts);
	}

	/**
	 * AES 解密操作
	 *
	 * @param str 待解密内容
	 * @return 密文
	 * @throws SafeCryptoException  解密异常
	 */
 	public String decrypt(String str) throws SafeCryptoException {
		byte[] bts = SafeEncodeUtils.base64Decode(str);
		bts = decrypt(bts);
		return new String(bts, SafeEncodeUtils.Charsets.UTF_8);
	}

	public byte[] encrypt(byte[] bts) throws SafeCryptoException {

		try {
			// 创建密码器
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);

			// 初始化为加密模式的密码器
			cipher.init(Cipher.ENCRYPT_MODE, getSecretKey());
			
			return cipher.doFinal(bts); //加密
		} catch (IllegalBlockSizeException e) {
			throw new SafeCryptoException(e);
		} catch (BadPaddingException e) {
			throw new SafeCryptoException(e);
		} catch (InvalidKeyException e) {
			throw new SafeCryptoException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SafeCryptoException(e);
		} catch (NoSuchPaddingException e) {
			throw new SafeCryptoException(e);
		}
	}

	/**
	 * AES 解密操作
	 *
	 * @param bts 密文
	 * @return 明文
	 * @throws SafeCryptoException  解密异常
	 */
	public byte[] decrypt(byte[] bts)	throws SafeCryptoException {
		try {
			// 实例化
			Cipher cipher = Cipher.getInstance(cipherAlgorithm);
	
			// 使用密钥初始化，设置为解密模式
			cipher.init(Cipher.DECRYPT_MODE, getSecretKey());
	
			return cipher.doFinal(bts); //解密
		} catch (IllegalBlockSizeException e) {
			throw new SafeCryptoException(e);
		} catch (BadPaddingException e) {
			throw new SafeCryptoException(e);
		} catch (InvalidKeyException e) {
			throw new SafeCryptoException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SafeCryptoException(e);
		} catch (NoSuchPaddingException e) {
			throw new SafeCryptoException(e);
		}
	}

	/**
	 * 获取加密算法
	 * @return 加密算法名称
	 */
	public String getCipherAlgorithm() {
		return this.cipherAlgorithm;
	}

	/**
	 * 更新加密算法
	 * @param algorithm 算法名称
	 * @throws SafeCryptoException 更新异常
	 */
	public void setCipherAlgorithm(String algorithm) throws SafeCryptoException {
		try {
			this.maxKeySize = Cipher.getMaxAllowedKeyLength(algorithm);
			this.cipherAlgorithm = algorithm;
		} catch (NoSuchAlgorithmException e) {
			throw new SafeCryptoException(e);
		}
	}

	/**
	 * 获取密钥转换算法
	 * @return 密钥转换算法
	 */
	public KeyAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}

	/**
	 * 设置密钥转换算法
	 * @param keyAlgorithm 密钥转换算法
	 */
	public void setKeyAlgorithm(KeyAlgorithm keyAlgorithm) {
		this.keyAlgorithm = keyAlgorithm;
	}

	/**
	 * 最大密钥长度（以位为单位） 或 Integer.max_value
	 * @return 最大密钥长度
	 */
	public int getMaxKeySize() {
		return maxKeySize;
	}

	/**
	 * 生成加密秘钥
	 *
	 * @return SecretKeySpec 加密秘钥
	 * @throws NoSuchAlgorithmException 算法不存在异常
	 */
	private SecretKeySpec getSecretKey() throws NoSuchAlgorithmException {
		byte[] encodedKey;
		if(keyAlgorithm == KeyAlgorithm.SHA1PRNG) {
			// 返回生成指定算法密钥生成器的 KeyGenerator 对象
			KeyGenerator kg = null;
			kg = KeyGenerator.getInstance(KEY_ALGORITHM);
			// AES 要求密钥长度为 128
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(secretKey);
			kg.init(maxKeySize, secureRandom);
			// 生成一个密钥
			encodedKey = kg.generateKey().getEncoded();
		} else { //KeyAlgorithm.PLAIN
			int keyBytes = maxKeySize / 8;
			if(maxKeySize % 8 != 0) {
				keyBytes++;
			}
			if(keyBytes == secretKey.length) {
				encodedKey = secretKey;
			} else {
				encodedKey = new byte[keyBytes];
				if(keyBytes > secretKey.length) {
					System.arraycopy(secretKey, 0, encodedKey, 0, secretKey.length);
					for(int i=secretKey.length; i<keyBytes; i++) {
						encodedKey[i] = 0;
					}
				} else {
					System.arraycopy(secretKey, 0, encodedKey, 0, keyBytes);
				}
			}

		}
		// 转换为AES专用密钥
		return new SecretKeySpec(encodedKey, KEY_ALGORITHM);
	}


}
