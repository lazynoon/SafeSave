package test;

import net_io.utils.NetLog;
import test.sample.EncryptionHelper;

/**
 * 单例测试类
 *
 * @author Hansen
 * @Date 2020-11-28
 */
public class SimpleTest {

	public static void main(String[] args) throws Exception {
		NetLog.LOG_LEVEL = NetLog.INFO;
		long startTime = System.currentTimeMillis();
		for(int i=0; i<10000; i++) {
			String originStr = System.currentTimeMillis() + "|" + Math.random();
			//String originStr = "123456";
			String encryptStr = EncryptionHelper.encryptString(originStr);
			String decryptStr = EncryptionHelper.decryptString(encryptStr);
			if(i % 100 == 0 || !originStr.equals(decryptStr)) {
				NetLog.logInfo("loop - " + i);
				NetLog.logInfo("\toriginStr: " + originStr.length() + ", " + originStr);
				NetLog.logInfo("\tencryptStr: " + encryptStr.length() + ", " + encryptStr);
				NetLog.logInfo("\tdecryptStr: " + decryptStr.length() + ", " + decryptStr);
			}
			if (!originStr.equals(decryptStr)) {
				NetLog.logWarn("encrypt error!");
				break;
			}
		}
		long costTime = System.currentTimeMillis() - startTime;
		NetLog.logInfo("CostTime: "+costTime+"ms");
		String[] sourceArr = {"A", "12345", "123456", "0123456789", "01234567890123456789",
			"12345|0123456789ABCDE|", "12345|0123456789ABCDE|1"};
		for(String sourceStr : sourceArr) {
			byte[] encryptedData = EncryptionHelper.encryptBytes(sourceStr.getBytes());
			NetLog.logInfo(sourceStr + " 加密后数据长度：" + encryptedData.length);
			NetLog.logInfo(sourceStr + " 解密数据: " + EncryptionHelper.decryptBytes(encryptedData).toString());
		}
		NetLog.logInfo("DONE");
	}

}
