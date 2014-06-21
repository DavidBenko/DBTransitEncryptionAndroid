import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

/**
 * Created by prndl2 on 6/20/14.
 */
abstract class DBTransitStringEncryptor extends DBTransitMixerEncryptor {
    public String stringEncoding;

    public DBTransitStringEncryptor(byte[] x509PublicKeyData) throws GeneralSecurityException {
        super(x509PublicKeyData);
        stringEncoding = "UTF-8";
    }

    public void encryptString(String string, EncryptorCallback callback) throws GeneralSecurityException{
        encryptData(string.getBytes(), callback);
    }

    public String decryptString(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] decryptedData = decryptData(data, key, iv);
        String decryptedStr =  new String(decryptedData, stringEncoding);
        decryptedData = null;
        return decryptedStr;
    }

    public void encryptString(String string, final IVMixerInterface ivMixer, final EncryptorCallback callback) throws GeneralSecurityException
    {
        byte[] data = string.getBytes();
        encryptData(data,ivMixer,callback);
    }

    public String decryptString(byte[] data, byte[] key, IVSeparatorInterface ivSeparator) throws GeneralSecurityException, UnsupportedEncodingException
    {
        byte[] decrypted = decryptData(data,key,ivSeparator);
        String decryptedStr = new String(decrypted, stringEncoding);
        decrypted = null;
        return decryptedStr;
    }
}
