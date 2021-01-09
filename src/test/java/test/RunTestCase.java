package test;

import net_io.utils.NetLog;
import test.sample.SourceBytesHelper;
import test.testcase.TestEncryptDecrypt;
import test.testcase.TestEncryptSourceData;
import test.testcase.TestUtilsMethod;

/**
 * 测试用例启动类
 *
 * @author Hansen
 * @Date 2020-12-05
 */
public class RunTestCase {
	private static byte[][] sourceData = SourceBytesHelper.generateRandomBytes(2048, 3);

	public static void main(String[] args) throws Exception {
		NetLog.LOG_LEVEL = NetLog.INFO;
		new TestEncryptSourceData().runTest();
		new TestEncryptDecrypt(sourceData).runTest();
		new TestUtilsMethod(sourceData).runTest();

	}
}
