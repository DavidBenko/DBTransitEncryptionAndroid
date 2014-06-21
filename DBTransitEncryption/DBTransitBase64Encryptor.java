import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import android.util.Base64;

/**
 * Created by davidbenko on 6/21/14.
 */
public class DBTransitBase64Encryptor extends DBTransitStringEncryptor {

    public interface EncryptorBase64Callback {
        void onComplete(String base64Key, String base64Data, String base64IV) throws GeneralSecurityException;
    }

    public DBTransitBase64Encryptor(byte[] x509PublicKeyData) throws GeneralSecurityException {
        super(x509PublicKeyData);
    }

    public void encryptAndBase64EncodeData(byte[] data, final IVMixerInterface ivMixer, final EncryptorBase64Callback callback) throws GeneralSecurityException
    {
        encryptData(data, ivMixer, new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                String base64Key = Base64.encodeToString(key,0);
                String base64Data = Base64.encodeToString(encryptedData,0);
                String base64IV = Base64.encodeToString(iv,0);
                callback.onComplete(base64Key,base64Data,base64IV);
            }
        });
    }

    public void encryptAndBase64EncodeData(byte[] data, final EncryptorBase64Callback callback) throws GeneralSecurityException
    {
        encryptData(data, new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                String base64Key = Base64.encodeToString(key,0);
                String base64Data = Base64.encodeToString(encryptedData,0);
                String base64IV = Base64.encodeToString(iv, 0);
                callback.onComplete(base64Key,base64Data,base64IV);
            }
        });
    }

    public void encryptAndBase64EncodeString(String string, final EncryptorBase64Callback callback) throws GeneralSecurityException {
        encryptString(string, new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                String base64Key = Base64.encodeToString(key, 0);
                String base64Data = Base64.encodeToString(encryptedData,0);
                String base64IV = Base64.encodeToString(iv,0);
                callback.onComplete(base64Key,base64Data,base64IV);
            }
        });
    }

    public void encryptAndBase64EncodeString(String string, final DBTransitMixerEncryptor.IVMixerInterface ivMixer, final EncryptorBase64Callback callback) throws GeneralSecurityException
    {
        encryptString(string, ivMixer, new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                String base64Key = Base64.encodeToString(key,0);
                String base64Data = Base64.encodeToString(encryptedData,0);
                String base64IV = Base64.encodeToString(iv,0);
                callback.onComplete(base64Key,base64Data,base64IV);
            }
        });
    }

    public byte[] base64DecodeAndDecryptData(String base64Data, String base64Key, String base64IV) throws GeneralSecurityException
    {
        byte[] data = Base64.decode(base64Data, 0);
        byte[] key = Base64.decode(base64Key, 0);
        byte[] iv = Base64.decode(base64IV,0);
        return decryptData(data,key,iv);
    }

    public byte[] base64DecodeAndDecryptData(String base64Data, String base64Key, IVSeparatorInterface ivSeparator) throws GeneralSecurityException
    {
        byte[] data = Base64.decode(base64Data, 0);
        byte[] key = Base64.decode(base64Key, 0);
        return decryptData(data,key,ivSeparator);
    }

    public String base64DecodeAndDecryptString(String base64Data, String base64Key, String base64IV) throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] data = Base64.decode(base64Data, 0);
        byte[] key = Base64.decode(base64Key, 0);
        byte[] iv = Base64.decode(base64IV,0);
        return decryptString(data,key,iv);
    }

    public String base64DecodeAndDecryptString(String base64Data, String base64Key, DBTransitMixerEncryptor.IVSeparatorInterface ivSeparator) throws GeneralSecurityException, UnsupportedEncodingException
    {
        byte[] data = Base64.decode(base64Data, 0);
        byte[] key = Base64.decode(base64Key, 0);
        return decryptString(data,key,ivSeparator);
    }
}
