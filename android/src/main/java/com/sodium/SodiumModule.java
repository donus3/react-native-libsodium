package com.sodium;

/**
 * Created by Donus on 12/13/2017.
 */
import android.util.Base64;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;

import org.libsodium.jni.SodiumConstants;
import org.libsodium.jni.crypto.Box;
import org.libsodium.jni.encoders.Encoder;
import org.libsodium.jni.keys.KeyPair;
import org.libsodium.jni.keys.SigningKey;
import org.libsodium.jni.keys.VerifyKey;

import java.util.HashMap;
import java.util.Map;

public class SodiumModule extends ReactContextBaseJavaModule {
    public static final int BASE64_SAFE_URL_FLAGS = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

    public SodiumModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "Sodium";
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put("SECRET_KEY_BYTE", SodiumConstants.SECRETKEY_BYTES);
        constants.put("PUBLIC_KEY_BYTES", SodiumConstants.PUBLICKEY_BYTES);
        constants.put("NONCE_BYTES", SodiumConstants.NONCE_BYTES);
        constants.put("SIGNATURE_BYTES", SodiumConstants.SIGNATURE_BYTES);
        constants.put("SHA256BYTES", SodiumConstants.SHA256BYTES);
        constants.put("ZERO_BYTES", SodiumConstants.ZERO_BYTES);
        constants.put("AEAD_CHACHA20_POLY1305_ABYTES", SodiumConstants.AEAD_CHACHA20_POLY1305_ABYTES);
        constants.put("AEAD_CHACHA20_POLY1305_KEYBYTES", SodiumConstants.AEAD_CHACHA20_POLY1305_KEYBYTES);
        constants.put("AEAD_CHACHA20_POLY1305_NPUBBYTES", SodiumConstants.AEAD_CHACHA20_POLY1305_NPUBBYTES);
        constants.put("BLAKE2B_OUTBYTES", SodiumConstants.BLAKE2B_OUTBYTES);
        constants.put("BOXZERO_BYTES", SodiumConstants.BOXZERO_BYTES);
        constants.put("SCALAR_BYTES", SodiumConstants.SCALAR_BYTES);
        constants.put("SHA512BYTES", SodiumConstants.SHA512BYTES);
        constants.put("XSALSA20_POLY1305_SECRETBOX_KEYBYTES", SodiumConstants.XSALSA20_POLY1305_SECRETBOX_KEYBYTES);
        constants.put("XSALSA20_POLY1305_SECRETBOX_NONCEBYTES", SodiumConstants.XSALSA20_POLY1305_SECRETBOX_NONCEBYTES);
        return constants;
    }

    @ReactMethod
    public void generateBoxKeypairs(Promise promise){
        KeyPair encryptionKeyPair = new KeyPair();
        WritableMap map = Arguments.createMap();
        map.putString("PublicKey", encryptionKeyPair.getPublicKey().toString());
        map.putString("SecretKey",  encryptionKeyPair.getPrivateKey().toString());
        promise.resolve(map);
    }

    @ReactMethod
    public void generateSignKeypairs(Promise promise){
        SigningKey signingKey = new SigningKey();
        VerifyKey verifyKey = signingKey.getVerifyKey();
        WritableMap map = Arguments.createMap();
        map.putString("SigningKey", signingKey.toString());
        map.putString("VerifyKey", verifyKey.toString());
        promise.resolve(map);
    }

    @ReactMethod
    public void encrypt(String message, String nonce, String publicKey, String secretKey, Promise promise){
        byte[] encryptionPublicKey = Encoder.HEX.decode(publicKey);
        byte[] encryptionPrivateKey = Encoder.HEX.decode(secretKey);
        Box box = new Box(encryptionPublicKey, encryptionPrivateKey);

        byte[] bmessage = message.getBytes();
        byte[] bnonce = nonce.getBytes();
        byte[] cipher = box.encrypt(bnonce, bmessage);
        WritableMap map = Arguments.createMap();
        map.putString("Cipher", Encoder.HEX.encode(cipher));
        promise.resolve(map);
    }

    @ReactMethod
    public void decrypt(String ciphertext, String nonce, String publicKey, String secretKey, Promise promise){
        byte[] encryptionPublicKey = Encoder.HEX.decode(publicKey);
        byte[] encryptionPrivateKey = Encoder.HEX.decode(secretKey);
        Box box = new Box(encryptionPublicKey, encryptionPrivateKey);

        byte[] bciphertext = Encoder.HEX.decode(ciphertext);
        byte[] bnonce = nonce.getBytes();
        byte[] decipher = box.decrypt(bnonce, bciphertext);
        WritableMap map = Arguments.createMap();
        try {
            map.putString("Decipher", new String(decipher, "UTF-8"));
        } catch (Exception e) {
            promise.reject(e);
        }
        promise.resolve(map);
    }

    @ReactMethod
    public void sign(String message, String signingKey, Promise promise){
        SigningKey signingKeyObj = new SigningKey(Encoder.HEX.decode(signingKey));
        byte[] signature = signingKeyObj.sign(message.getBytes());
        WritableMap map = Arguments.createMap();
        map.putString("Signature", Encoder.HEX.encode(signature));
        promise.resolve(map);
    }

    @ReactMethod
    public void verify(String signature, String message, String publicKey, Promise promise){
        VerifyKey verifyKey = new VerifyKey(Encoder.HEX.decode(publicKey));
        boolean isValid = verifyKey.verify(message.getBytes(), Encoder.HEX.decode(signature));
        WritableMap map = Arguments.createMap();
        map.putBoolean("isValid", isValid);
        promise.resolve(map);
    }
}