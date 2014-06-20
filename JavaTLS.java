import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by davidbenko on 5/21/14.
 */

public class JavaTLS {
    private static final String RSA_TRANSFORM = "RSA/ECB/PKCS1Padding";
    private static final String X509_ALGORITHM = "X509";
    private static final String RSA_PRIVATE_TRANSFORM = "PKCS12";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding";

    private static final Integer ALGORITHM_KEY_SIZE = 16;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    //================================================================================
    // Init
    //================================================================================

    public JavaTLS(byte[] x509PublicKeyData) throws GeneralSecurityException{
        this.publicKey = loadPublicKey(x509PublicKeyData);
    }

    //================================================================================
    // RSA Key Parse
    //================================================================================

    private PublicKey loadPublicKey(byte[] keyBytes) throws GeneralSecurityException{
        CertificateFactory certificateFactory = CertificateFactory.getInstance(X509_ALGORITHM);
        Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(keyBytes));
        return certificate.getPublicKey();
    }

    private PrivateKey loadPrivateKey(InputStream inputStream, String keyAlias, String password) throws GeneralSecurityException, IOException{
        KeyStore keystore = KeyStore.getInstance(RSA_PRIVATE_TRANSFORM);//KeyStore.getDefaultType());
        keystore.load(inputStream, password.toCharArray());
        return (PrivateKey)keystore.getKey(keyAlias, password.toCharArray());
    }

    //================================================================================
    // Private Key (.p12)
    //================================================================================

    public void setPrivateKey(InputStream inputStream, String keyAlias, String password) throws GeneralSecurityException, IOException{
        this.privateKey = loadPrivateKey(inputStream,keyAlias,password);
    }

    //================================================================================
    // Random Data Generation
    //================================================================================

    private byte[] getRandomData(byte[] data){
        SecureRandom ranGen = new SecureRandom();
        ranGen.nextBytes(data);
        return data;
    }

    public byte[] generateKey(){
        byte[] key = new byte[ALGORITHM_KEY_SIZE];
        return getRandomData(key);
    }

    //================================================================================
    // RSA Encryption
    //================================================================================

    public byte[] rsaEncryptData(byte[]data) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        return cipher.doFinal(data);
    }

    //================================================================================
    // RSA Decryption
    //================================================================================

    public byte[] rsaDecryptData(byte[]data) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORM);
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        return cipher.doFinal(data);
    }

    //================================================================================
    // AES Encryption
    //================================================================================

    public  byte[] encryptPayload(byte[] data, byte[] key) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    //================================================================================
    // AES Decryption
    //================================================================================

    public byte[] decryptPayload(byte[] data, byte[] key) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
}
