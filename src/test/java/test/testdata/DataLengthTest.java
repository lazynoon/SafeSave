package test.testdata;

import com.lazynoon.commons.safesave.SafeCryptoException;
import com.lazynoon.commons.safesave.SafeData;
import com.lazynoon.commons.safesave.utils.SafeByteUtils;
import net_io.core.StatNIO;
import net_io.utils.EncodeUtils;
import net_io.utils.NetLog;
import test.sample.EncryptionHelper;
import test.sample.SourceBytesHelper;

public class DataLengthTest {
	private static byte[][] sourceData = SourceBytesHelper.generateRandomBytes(1024, 1);

	private static void testBase64Length() throws SafeCryptoException {
		long startTime = System.nanoTime();
		int totalBytes = 0;
		int totalRows = 0;
		int lastBase64Length = 0;
		for(byte[] originData : sourceData) {
			byte[] encryptData = EncryptionHelper.encryptBytes(originData);
			String base64Str = EncodeUtils.encodeBase64ToString(encryptData);
			SafeData safeData = EncryptionHelper.decryptBytes(encryptData);
			byte[] decryptData = safeData.getPlaintextData();
			if(originData.length != decryptData.length || SafeByteUtils.isEqual(originData, decryptData) == false) {
				throw new SafeCryptoException(20100721, "encrypt & decrypt not equal." +
						" source data length: "+originData.length +
						", decrypt data length: "+decryptData.length);
			}
			if(base64Str.length() != lastBase64Length) {
				lastBase64Length = base64Str.length();
				NetLog.logInfo("origin length: " + originData.length
						+ ", encrypt length: " + encryptData.length + ", base64 length: " + lastBase64Length);
			}
			totalRows++;
			totalBytes += originData.length;
		}
		double costTime = (System.nanoTime() - startTime) / StatNIO.ONE_MILLION_DOUBLE;
		NetLog.logInfo("PASS - testBase64Length, " +
				"totalRows: " + totalRows +", " +
				"totalBytes: " + totalBytes +", " +
				"costTime: " + costTime + "ms");

	}
	public static void main(String[] args) throws SafeCryptoException {
		NetLog.LOG_LEVEL = NetLog.INFO;
		testBase64Length();
	}
}
