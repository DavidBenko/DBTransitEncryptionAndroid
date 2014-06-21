package com.mastercard.loyaltyrtr.dbtransitencryption.app.DBTransitEncryptionAndroid;

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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by davidbenko on 5/21/14.
 */

public class JavaTLS {
    private static final String LOG_TAG = "DBTransitEncryption";

    private static final String RSA_TRANSFORM = "RSA/ECB/PKCS1Padding";
    private static final String X509_ALGORITHM = "X509";
    private static final String RSA_PRIVATE_TRANSFORM = "PKCS12";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORM = "AES/CBC/PKCS5Padding";

    private static final Integer ALGORITHM_KEY_SIZE = 16;
    private static final Integer ALGORITHM_IV_SIZE = 16;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public interface EncryptorCallback {
        void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException;
    }

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

    private byte[] generateKey(){
        byte[] key = new byte[ALGORITHM_KEY_SIZE];
        return getRandomData(key);
    }

    private byte[] generateIV(){
        byte[] iv = new byte[ALGORITHM_IV_SIZE];
        return getRandomData(iv);
    }

    //================================================================================
    // RSA Encryption
    //================================================================================

    private byte[] rsaEncryptData(byte[]data) throws GeneralSecurityException
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

    private void encryptPayload(byte[] data, final EncryptorCallback callback) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        byte[] key = generateKey();
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        byte[] iv = generateIV();
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        callback.onComplete(key, cipher.doFinal(data), iv);
    }

    //================================================================================
    // AES Decryption
    //================================================================================

    public byte[] decryptPayload(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance(TRANSFORM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    //================================================================================
    // AES Decryption
    //================================================================================

    public void encryptData(byte[] data, final EncryptorCallback callback) throws GeneralSecurityException
    {
        encryptPayload(data,new EncryptorCallback() {
            @Override
            public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException{
                byte[] rsaEncryptedKey = rsaEncryptData(key);
                callback.onComplete(rsaEncryptedKey,encryptedData,iv);
            }
        });
    }

}
