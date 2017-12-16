# react-native-libsodium
libsodium wrapper for React Native

Mark : Currently support only Android.

## Install

```
yarn add react-native-libsodium
```

```
react-native link
```


## Android Config
 * AndroidManifest.xml

 ```
<manifest
    ...

    xmlns:tools="http://schemas.android.com/tools"

    ...>

    <application

        ...

        tools:replace="android:allowBackup"

        ...>

        ...

    </application>

    ...

</manifest>
 ```

* android/app/build.gradle

```
android {
    compileSdkVersion 25
    buildToolsVersion "25.0.3"
...
    defaultConfig {
      targetSdkVersion 25
```

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
