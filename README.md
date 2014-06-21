DBTransitEncryption (Android)
=====================

Overview
---------

Port of [DBTransitEncryption](https://github.com/DavidBenko/DBTransitEncryption) to Android.
Transport Layer Security for securing data payloads in Java. An easy way to secure data by providing a symmetric key for that transaction. Keys are generated on the fly and every message will have a new key. 

**TL;DR** AES encrypts data with a random key, RSA encrypts key and provides both.

### What does it do?
**DBTransitEncryption** will secure data for transit similar to the handshake protocol of TLS. 
- Generate AES symmetric key
- Encrypt data payload with AES key
- Encrypt AES key with X.509 RSA public key
- Returns AES-encrypted payload and RSA-encrypted symmetric key 

### Generate X.509 RSA Key Pair
- Run the following commands to generate a personal key pair for testing. 
- The files you care about are `public_key.der` and `private_key.p12`

```shell
openssl req -x509 -out public_key.der -outform der -new -newkey rsa:1024 -keyout private_key.pem -days 3650
openssl x509 -inform der -outform pem -in public_key.der -out public_key.pem
openssl pkcs12 -export -in public_key.pem -inkey private_key.pem -out private_key.p12
```



Encryption
---------

### Using in-memory X.509 Public Key
```java
    final String publicKeyContent = "MIIDvzCCAyigAwI...."; // Base64 encoded key
    byte [] publicKey = Base64.decode(publicKeyContent, 0);
    
    try{
            DBTransitEncryptor encryptor = new DBBaseEncryptor(publicKey);
    }
    catch (GeneralSecurityException e){}
```

### Encrypt byte[]
```java

  String firstData = "hello world";
  try{
          DBBaseEncryptor encryptor = new DBBaseEncryptor(publicKey);
          encryptor.encryptData(firstData.getBytes(), new DBBaseEncryptor.EncryptorCallback() {
                @Override
                public void onComplete(byte[] key, byte[] encryptedData, byte[] iv) throws GeneralSecurityException {
                    // Encrypted data is available here
                }
            });
  }
  catch (GeneralSecurityException e){}
```

Decryption
---------

### Using Bundled PKCS#12 RSA Private Key (.p12)
```java
  final String privateKeyAlias = "6df39e5383f8932jsand93j008972kjs8wwqwq87";
  final AssetManager assetMgr = getResources().getAssets();
  
  DBBaseEncryptor encryptor = new DBBaseEncryptor(publicKey);
  encryptor.setPrivateKey(assetMgr.open("private_key.p12"),privateKeyAlias,"password");
```

### Decrypt byte[]
```java
  DBBaseEncryptor encryptor = new DBBaseEncryptor(publicKey);
  encryptor.setPrivateKey(assetMgr.open("private_key.p12"),privateKeyAlias,"password");
  
  byte[] decryptedData = encryptor.decryptData(encryptedData, key, iv);
```

IV Mixer Blocks
---------
**DBTransitEncryption** allows you to define custom blocks to mix and separate the initialization vector with the key and/or the encrypted data. 

The `ivMixer` gives access to the data, key, and iv immediately after the data is encrypted, but before the key is encrypted. This allows you to mix the iv with key before it is RSA encrypted, to further secure the iv.

The `ivSeparator` is the opposite of the `ivMixer`. The `ivSeparator` should be implemented in a way which undoes the mixing algorithm and returns the iv. **The `ivSeparator` is only needed for decryption.**


License
---------------

The MIT License (MIT)

Copyright (c) 2014 David Benko

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
