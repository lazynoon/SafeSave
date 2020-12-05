package test.testcase;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.utils.SafeMathUtils;
import net_io.core.StatNIO;
import net_io.utils.NetLog;

/**
 * 常用类方法测试
 *
 * @author Hansen
 * @Date 2020-12-05
 */
public class TestUtilsMethod {
	private byte[][] sourceData;

	public TestUtilsMethod(byte[][] sourceData) {
		this.sourceData = sourceData;
	}

	public void runTest() throws SafeCryptoException {
		testMathUtils();
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
				"costTime: " + costTime + "ms");
	}

}
