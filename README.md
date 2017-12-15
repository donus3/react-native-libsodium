# react-native-libsodium
libsodium wrapper for React Native

Currently functionality is limited to just on Android

## Provide API

### generateBoxKeypairs (async)
input :-

output :
```
{
    PublicKey: PublicKey,
    SecretKey: SecretKey
}
```
* PublicKey string (hex)
* SecretKey string (hex)

### generateSignKeypairs (async)
input :-

output :
```
{
    SigningKey: SigningKey,
    VerifyKey: VerifyKey
}
```
* SigningKey string (hex)
* VerifyKey string (hex)

### encrypt (async)
input : (msg, nonce, publicKey, secretKey)
* msg string
* nonce string
* publickey string (hex)
* secretkey string (hex)
output : Cipher string

### decrypt (async)
input : (msg, nonce, publicKey, secretKey)
* msg string
* nonce string
* publickey string (hex)
* secretkey string (hex)
output : message string

### sign (async)
input : (msg, secretKey)
* msg string
* secretkey string (hex)
output : Signature string (hex)

### verify
input : (signature, msg, secretKey)
* signature string (hex)
* msg string
* secretKey string (hex)
ouput: isValid boolen

## Next Step
more libsodium api wrapper and support ios

## Credit
libsodium-jni (https://github.com/joshjdevl/libsodium-jni)
