package com.lazynoon.commons.safesave.utils;

/**
 * 常用数学类
 *
 * @author Hansen
 * @date 2020-11-15
 */
public class SafeMathUtils {
	/** long型首字节二进制全1数 **/
	private static final long MASK_LONG_1_BYTE = 0xFFL;
	/** int型首字节二进制全1数 **/
	private static final int MASK_INT_1_BYTE = 0xFF;

	/**
	 * 从字节数组，按高字节在前的存储方式，解析一个 long 型数字
	 *   注意：若取数的位置，不在字节数组的范围内，抛出异常 IndexOutOfBoundsException
	 * @param data 字节数组
	 * @param offset 解析数据的偏移量
	 * @param byteCount 取字节数量（最小1，最大8）
	 * @return long型数字（允许负数）
	 */
	public static long parseLongAsBigEndian(byte[] data, int offset, int byteCount) {
		if(byteCount <= 0 || byteCount > 8) {
			throw new IndexOutOfBoundsException("Can not parse long number. byteCount: " + byteCount);
		}
		if(data == null || offset < 0 || offset + byteCount > data.length) {
			throw new IndexOutOfBoundsException("Can not parse long number. offset: " + offset);
		}
		long result = 0;
		int k = (byteCount - 1) * 8;
		while(k >= 0) {
			long num = ((long) data[offset++]) & MASK_LONG_1_BYTE;
			if(k > 0) {
				result |= num << k;
			} else {
				result |= num;
			}
			k -= 8;
		}
		return result;
	}

	/**
	 * 从字节数组，按高字节在前的存储方式，解析一个 int 型数字
	 *   注意：若取数的位置，不在字节数组的范围内，抛出异常 IndexOutOfBoundsException
	 * @param data 字节数组
	 * @param offset 解析数据的偏移量
	 * @param byteCount 取字节数量（最小1，最大4）
	 * @return int型数字（允许负数）
	 */
	public static int parseIntAsBigEndian(byte[] data, int offset, int byteCount) {
		if(byteCount <= 0 || byteCount > 4) {
			throw new IndexOutOfBoundsException("Can not parse integer number. byteCount: " + byteCount);
		}
		if(data == null || offset < 0 || offset + byteCount > data.length) {
			throw new IndexOutOfBoundsException("Can not parse integer number. offset: " + offset);
		}
		int result = 0;
		int k = (byteCount - 1) * 8;
		while(k >= 0) {
			int num = ((int) data[offset++]) & MASK_INT_1_BYTE;
			if(k > 0) {
				result |= num << k;
			} else {
				result |= num;
			}
			k -= 8;
		}
		return result;
	}

	/**
	 * 从字节数组，按高字节在前的存储方式，解析一个 short 型数字
	 *   注意：若取数的位置，不在字节数组的范围内，抛出异常 IndexOutOfBoundsException
	 * @param data 字节数组
	 * @param offset 解析数据的偏移量
	 * @param byteCount 取字节数量（最小1，最大2）
	 * @return short型数字（允许负数）
	 */
	public static short parseShortAsBigEndian(byte[] data, int offset, int byteCount) {
		if(byteCount <= 0 || byteCount > 2) {
			throw new IndexOutOfBoundsException("Can not parse short number. byteCount: " + byteCount);
		}
		if(data == null || offset < 0 || offset + byteCount > data.length) {
			throw new IndexOutOfBoundsException("Can not parse short number. offset: " + offset);
		}
		int result = ((int) data[offset]) & MASK_INT_1_BYTE;
		if(byteCount > 1) {
			result <<= 8;
			result |= ((int) data[offset+1]) & MASK_INT_1_BYTE;
		}
		return (short)result;
	}
}
