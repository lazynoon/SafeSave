package test.sample;

import com.lazynoon.commons.safesave.utils.SafeEncodeUtils;

/**
 * 加密数据源生成类
 *
 * @author Hansen
 * @Date 2020-11-28
 */
public class SourceBytesHelper {
	public static byte[][] generateRandomBytes(int rowNum, int colNum) {
		byte[][] result = new byte[rowNum*colNum][];
		for(int rowId=1; rowId<=rowNum; rowId++) {
			int offset = (rowId - 1) * colNum;
			for(int i=0; i<colNum; i++) {
				byte[] node = new byte[rowId];
				for(int j=0; j<rowId; j++) {
					node[j] = (byte)Math.round(Math.random() * 0xFFFF);
				}
				result[offset+i] = node;
			}
		}
		return result;
	}

	public static String formatRandomBytes(byte[][] randomBytes) {
		StringBuilder builder = new StringBuilder();
		for(int i=0; i<randomBytes.length; i++) {
			builder.append(SafeEncodeUtils.encodeBase64ToString(randomBytes[i]));
			builder.append("\n");
		}
		return builder.toString();
	}

	public static byte[][] parseRandomBytes(String randomStr) {
		if(randomStr == null) {
			return null;
		}
		String[] lineArr = randomStr.split("\n");
		byte[][] result = new byte[lineArr.length][];
		for(int i=0; i<lineArr.length; i++) {
			String line = lineArr[i];
			line = line.trim();
			if(line.length() == 0) {
				continue;

			}
			result[i] = SafeEncodeUtils.decodeBase64(line);
		}
		return result;
	}
}
