import java.security.GeneralSecurityException;

/**
 * Created by davidbenko on 6/21/14.
 */
abstract class DBTransitMixerEncryptor extends DBBaseEncryptor {

    public static class IVMix{
        public byte[] data;
        public byte[] key;
    }

    public static class IVSeparate{
        public byte[] data;
        public byte[] key;
        public byte[] iv;
    }

    public interface IVMixerInterface {
        IVMix ivMixer(byte[] data, byte[] key, byte[] iv)throws GeneralSecurityException;
    }
    public interface IVSeparatorInterface {
        IVSeparate ivSeparator(byte[] data, byte[] key) throws GeneralSecurityException;
    }

    public DBTransitMixerEncryptor(byte[] x509PublicKeyData) throws GeneralSecurityException{
        super(x509PublicKeyData);
    }

    public void encryptData(byte[] data, final IVMixerInterface ivMixer, final EncryptorCallback callback) throws GeneralSecurityException
    {
        encryptPayload(data, new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                IVMix mix = ivMixer.ivMixer(encryptedData,key,iv);
                byte[] rsaEncryptedKey = rsaEncryptData(mix.key);
                callback.onComplete(rsaEncryptedKey,mix.data,iv);
            }
        });
    }

    public byte[] decryptData(byte[] data, byte[] key, IVSeparatorInterface ivSeparator) throws GeneralSecurityException
    {
        byte[] decryptedKey = rsaDecryptData(key);
        IVSeparate sep = ivSeparator.ivSeparator(data,decryptedKey);
        return decryptPayload(sep.data,sep.key,sep.iv);
    }
}
