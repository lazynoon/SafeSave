package test.testcase;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.utils.SafeByteUtils;
import com.lazynoon.commons.safesave.utils.SafeMathUtils;
import net_io.core.StatNIO;
import net_io.myaction.CheckException;
import net_io.utils.NetLog;

/**
 * 常用类方法测试
 *
 * @author Hansen
 * @Date 2020-12-05
 */
public class TestUtilsMethod {
	private static final int BYTE_SIZE = 256;
	private byte[][] sourceData;

	public TestUtilsMethod(byte[][] sourceData) {
		this.sourceData = sourceData;
	}

	public void runTest() throws SafeCryptoException {
		testMathUtils();
		testIsByteMappingValid();
	}

	protected void testMathUtils() throws SafeCryptoException {
		long startTime = System.nanoTime();
		int totalBytes = 0;
		int totalRows = sourceData.length;
		int totalMatch1Byte = 0;
		int totalMatch2Byte = 0;
		for(int i=0; i<sourceData.length; i++) {
			byte[] row = sourceData[i];
			totalBytes += row.length;
			for(int j=0; j<row.length; j+=4) {
				if(j < row.length - 4) {
					long num1 = SafeMathUtils.parseLongAsBigEndian(row, j, 4);
					int num2 = SafeMathUtils.parseIntAsBigEndian(row, j, 4);
					int num3 = SafeMathUtils.parseIntAsBigEndian(row, j, 2);
					short num4 = SafeMathUtils.parseShortAsBigEndian(row, j, 2);
					if((int)num1 != num2) {
						throw new SafeCryptoException(20100731, "parse long and int not equal." +
								" i="+i+", j="+j+", num1="+num1+", num2="+num2);
					}
					if((short)num3 != num4) {
						throw new SafeCryptoException(20100732, "parse int and short not equal." +
								" i="+i+", j="+j+", num3="+num3+", num4="+num4);
					}
					totalMatch2Byte++;
				} else {
					short num1 = (short) (row[j] & 0xFF);
					long num2 = SafeMathUtils.parseLongAsBigEndian(row, j, 1);
					int num3 = SafeMathUtils.parseIntAsBigEndian(row, j, 1);
					short num4 = SafeMathUtils.parseShortAsBigEndian(row, j, 1);
					if(num1 != (short)num2 || num1 != (short)num3 || num1 != num4) {
						throw new SafeCryptoException(20100733, "parse 1 byte short not equal." +
								" i="+i+", j="+j+", num1="+num1+", num2="+num2+", num3="+num3+", num4="+num4);
					}
					totalMatch1Byte++;
				}
			}
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testMathUtils, " +
				"totalRows: " + totalRows +", " +
				"totalBytes: " + totalBytes +", " +
				"totalMatch1Byte: " + totalMatch1Byte +", " +
				"totalMatch2Byte: " + totalMatch2Byte +", " +
				"costTime: " + costTime + " ms");
	}

	protected void testIsByteMappingValid() throws SafeCryptoException {
		long startTime = System.nanoTime();
		//字节映射表
		byte[][] byteMappingPool = new byte[3][];
		for(int i=0; i<byteMappingPool.length; i++) {
			byteMappingPool[i] = new byte[BYTE_SIZE];
		}
		//加号生成
		for(int i=0; i<BYTE_SIZE; i++) {
			byteMappingPool[0][i] = (byte)(i + 5);
		}
		//移位生成
		for(int i=0; i<BYTE_SIZE; i++) {
			int num = i;
			num = (num << 1 |  num >>> 7) & 0xFF;
			byteMappingPool[1][i] = (byte)num;
		}
		//减号生成
		for(int i=0; i<BYTE_SIZE; i++) {
			byteMappingPool[2][i] = (byte)(i - 5);
		}
		//预期校验正确
		for(int i=0; i<byteMappingPool.length; i++) {
			byte[] byteMapping = byteMappingPool[i];
			if(!SafeByteUtils.isByteMappingValid(byteMapping)) {
				throw new SafeCryptoException(20100735, "isByteMappingValid verify fail. loop: " + i);
			}
		}
		for(int loop=0; loop<1024; loop++) {
			//修改1字节
			for (int i = 0; i < byteMappingPool.length; i++) {
				byte[] byteMapping = byteMappingPool[i];
				int num1 = (int) Math.round(Math.random() * 0xFFFF) % BYTE_SIZE;
				int num2 = (int) Math.round(Math.random() * 0xFFFF) % 127 + 1;
				byteMapping[num1] += num2;
			}
			//预期校验错误
			for (int i = 0; i < byteMappingPool.length; i++) {
				byte[] byteMapping = byteMappingPool[i];
				if (SafeByteUtils.isByteMappingValid(byteMapping)) {
					throw new SafeCryptoException(20100736, "isByteMappingValid verify fail. loop: " + i + "/" + loop);
				}
			}
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testIsByteMappingValid, costTime: " + costTime + " ms");
	}

}
