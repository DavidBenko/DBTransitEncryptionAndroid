import java.security.GeneralSecurityException;

/**
 * Created by davidbenko on 6/21/14.
 */
public final class DBTransitEncryptor extends DBTransitBase64Encryptor {
    public DBTransitEncryptor(byte[] x509PublicKeyData) throws GeneralSecurityException{
        super(x509PublicKeyData);
    }
}
