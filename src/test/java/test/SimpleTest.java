package test;

import com.lazynoon.commons.safesave.utils.SafeNetLog;
import test.sample.EncryptionHelper;

/**
 * 单例测试类
 *
 * @author Hansen
 * @Date 2020-11-28
 */
public class SimpleTest {

	public static void main(String[] args) throws Exception {
		SafeNetLog.LOG_LEVEL = SafeNetLog.INFO;
		long startTime = System.currentTimeMillis();
		for(int i=0; i<10000; i++) {
			String originStr = System.currentTimeMillis() + "|" + Math.random();
			//String originStr = "123456";
			String encryptStr = EncryptionHelper.encryptString(originStr);
			String decryptStr = EncryptionHelper.decryptString(encryptStr);
			if(i % 100 == 0 || !originStr.equals(decryptStr)) {
				SafeNetLog.logInfo("loop - " + i);
				SafeNetLog.logInfo("\toriginStr: " + originStr.length() + ", " + originStr);
				SafeNetLog.logInfo("\tencryptStr: " + encryptStr.length() + ", " + encryptStr);
				SafeNetLog.logInfo("\tdecryptStr: " + decryptStr.length() + ", " + decryptStr);
			}
			if (!originStr.equals(decryptStr)) {
				SafeNetLog.logWarn("encrypt error!");
				break;
			}
		}
		long costTime = System.currentTimeMillis() - startTime;
		SafeNetLog.logInfo("CostTime: "+costTime+"ms");
		String[] sourceArr = {"A", "12345", "123456", "0123456789", "01234567890123456789",
			"12345|0123456789ABCDE|", "12345|0123456789ABCDE|1"};
		for(String sourceStr : sourceArr) {
			byte[] encryptedData = EncryptionHelper.encryptBytes(sourceStr.getBytes());
			SafeNetLog.logInfo(sourceStr + " 加密后数据长度：" + encryptedData.length);
			SafeNetLog.logInfo(sourceStr + " 解密数据: " + EncryptionHelper.decryptBytes(encryptedData).toString());
		}
		SafeNetLog.logInfo("DONE");
	}

}
