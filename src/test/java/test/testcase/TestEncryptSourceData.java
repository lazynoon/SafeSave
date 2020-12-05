package test.testcase;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.utils.SafeByteUtils;
import net_io.core.StatNIO;
import net_io.utils.NetLog;
import test.sample.SourceBytesHelper;

/**
 * 加密数据源的文本编码与解码一致性测试
 *
 * @author Hansen
 * @Date 2020-12-05
 */
public class TestEncryptSourceData {

	public void runTest() throws SafeCryptoException {
		testGenerateRandom();
		testEncodeString();
	}

	protected void testGenerateRandom() throws SafeCryptoException {
		long startTime = System.nanoTime();
		int rowNum = 32;
		int colNum = 1;
		byte[][] sample = SourceBytesHelper.generateRandomBytes(rowNum, colNum);
		for(int i=0; i<1000; i++) {
			byte[][] data = SourceBytesHelper.generateRandomBytes(rowNum, colNum);
			if(SafeByteUtils.isEqual(sample, data)) {
				throw new SafeCryptoException(20100711,
						"testGenerateRandom not unique data, rowNum: "+rowNum+", colNum: "+colNum);
			}
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testGenerateRandom, costTime: " + costTime + "ms");
	}

	protected void testEncodeString() throws SafeCryptoException {
		long startTime = System.nanoTime();
		int rowNum = 3;
		int colNum = 8;
		for(int i=0; i<10; i++) {
			byte[][] sample = SourceBytesHelper.generateRandomBytes(rowNum, colNum);
			String str = SourceBytesHelper.formatRandomBytes(sample);
			byte[][] sample2 = SourceBytesHelper.parseRandomBytes(str);
			if(SafeByteUtils.isEqual(sample, sample2) == false) {
				throw new SafeCryptoException(20100712,
						"testEncodeString decode not equal, rowNum: "+rowNum+", colNum: "+colNum+", loop: "+i);
			}
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testEncodeString, costTime: " + costTime + "ms");
	}
}
