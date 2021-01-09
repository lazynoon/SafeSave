package com.lazynoon.commons.safesave.utils;


/**
 * 常用字节数组处理类
 *
 * @author Hansen
 * @date 2020-11-21
 */
public class SafeByteUtils {
	/**
	 * 根据字节映射表，转换
	 * 注意：字节映射表，必须唯一对应关系，接口内部不检查唯一性
	 * @param data 转换前数据
	 * @param byteMapping 字节映射表（共256字节）
	 * @return 按字节映射表，匹配后的值
	 */
	public static byte[] convertMapping(byte[] data, byte[] byteMapping) {
		if(data == null) {
			return null;
		}
		if(byteMapping == null || byteMapping.length != 256 || byteMapping[0] == byteMapping[255]) {
			throw new IllegalArgumentException("byteMapping length must be 256");
		}
		byte[] result = new byte[data.length];
		for(int i=0; i<data.length; i++) {
			int index = data[i] & 0xFF;
			result[i] = byteMapping[index];
		}
		return result;
	}

	/**
	 * 检查字节映射表是否正确
	 * @param byteMapping 字节映射表（共256字节）
	 * @return true OR false
	 */
	public static boolean isByteMappingValid(byte[] byteMapping) {
		if(byteMapping == null || byteMapping.length != 256) {
			return false;
		}
		int[] checkBuff = new int[256];
		for(int i=0; i<checkBuff.length; i++) {
			checkBuff[i] = -1;
		}
		for(int i=0; i<byteMapping.length; i++) {
			int num = byteMapping[i] & 0xFF;
			if(checkBuff[num] != -1) {
				return false;
			}
			checkBuff[num] = i;
		}
		return true;
	}

	/**
	 * 检查两字节数组的值，是否相等
	 * @param bts1 一维数组1
	 * @param bts2 一维数组2
	 * @return 值相等返回 true，否则返回 false
	 */
	public static boolean isEqual(byte[] bts1, byte[] bts2) {
		if(bts1 == null) {
			if(bts2 == null) {
				return true;
			} else {
				return false;
			}
		} else if(bts2 == null) {
			return false;
		}
		if(bts1.length != bts2.length) {
			return false;
		}
		for(int i=0; i<bts1.length; i++) {
			if(bts1[i] != bts2[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * 检查两字节数组的值，是否相等
	 * @param bts1 二维数组1
	 * @param bts2 二维数组2
	 * @return 值相等返回 true，否则返回 false
	 */
	public static boolean isEqual(byte[][] bts1, byte[][] bts2) {
		if(bts1 == null) {
			if(bts2 == null) {
				return true;
			} else {
				return false;
			}
		} else if(bts2 == null) {
			return false;
		}
		if(bts1.length != bts2.length) {
			return false;
		}
		for(int i=0; i<bts1.length; i++) {
			if(isEqual(bts1[i], bts2[i]) == false) {
				return false;
			}
		}
		return true;
	}
}
