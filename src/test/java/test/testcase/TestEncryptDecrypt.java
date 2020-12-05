package test.testcase;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.SafeData;
import com.lazynoon.commons.safesave.utils.SafeByteUtils;
import net_io.core.StatNIO;
import net_io.utils.NetLog;
import test.sample.EncryptionHelper;

/**
 * 加密数据解密后与源数据比较一致性测试
 *
 * @author Hansen
 * @Date 2020-12-05
 */
public class TestEncryptDecrypt {
	private byte[][] sourceData;

	public TestEncryptDecrypt(byte[][] sourceData) {
		this.sourceData = sourceData;
	}

	public void runTest() throws SafeCryptoException {
		testDecryptEqual();
	}

	protected void testDecryptEqual() throws SafeCryptoException {
		long startTime = System.nanoTime();
		int totalBytes = 0;
		int totalRows = 0;
		for(byte[] originData : sourceData) {
			byte[] encryptData = EncryptionHelper.encryptBytes(originData);
			SafeData safeData = EncryptionHelper.decryptBytes(encryptData);
			byte[] decryptData = safeData.getPlaintextData();
			if(SafeByteUtils.isEqual(originData, decryptData) == false) {
				throw new SafeCryptoException(20100721, "encrypt & decrypt not equal." +
						" source data length: "+originData.length +
						", decrypt data length: "+decryptData.length);
			}
			totalRows++;
			totalBytes += originData.length;
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testDecryptEqual, " +
				"totalRows: " + totalRows +", " +
				"totalBytes: " + totalBytes +", " +
				"costTime: " + costTime + "ms");
	}

}
