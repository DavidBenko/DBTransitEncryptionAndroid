package DavidBenko.DBTransitEncryptionAndroid;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

/**
 * Created by prndl2 on 6/20/14.
 */
public class DBTransitStringEncryptor extends JavaTLS {
    public String stringEncoding;

    public DBTransitStringEncryptor(byte[] x509PublicKeyData) throws GeneralSecurityException {
        super(x509PublicKeyData);
        stringEncoding = "UTF-8";
    }

    public void encryptString(String string, EncryptorCallback callback) throws GeneralSecurityException{
        encryptData(string.getBytes(), callback);
    }

    public String decryptString(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException, UnsupportedEncodingException {
        decryptData(data, key, iv);
        return new String(data, stringEncoding);
    }
}
