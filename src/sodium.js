import {NativeModules} from 'react-native';

const { Sodium } = NativeModules;

let SodiumAPI = {
    generateBoxKeypairs: async() => {
        try{
            var {PublicKey, SecretKey} = await Sodium.generateBoxKeypairs()
            return {
                PublicKey: PublicKey,
                SecretKey: SecretKey
            }
        } catch(e) {
            console.error
            return e
        }
    },
    generateSignKeypairs: async() => {
        try{
            var {SigningKey, VerifyKey} = await Sodium.generateSignKeypairs()
            return {
                SigningKey: SigningKey,
                VerifyKey: VerifyKey
            }
        } catch(e) {
            console.error
            return e
        }
    },
    encrypt: async(msg, nonce, publicKey, secretKey) => {
        try{
            var {Cipher} = await Sodium.encrypt(msg, nonce, publicKey, secretKey)
            return Cipher
        } catch(e) {
            console.error
            return e
        }
    },
    decrypt: async(msg, nonce, publicKey, secretKey) => {
        try{
            var {Decipher} = await Sodium.decrypt(msg, nonce, publicKey, secretKey)
            return Decipher
        } catch(e) {
            console.error
            return e
        }
    },
    sign: async(msg, secretKey) => {
        try {
            var {Signature} = await Sodium.sign(msg, secretKey)
            return Signature
        } catch(e) {
            console.error
            return e
        }
    },
    verify: async(signature, msg, secretKey) => {
        try {
            var {isValid} = await Sodium.verify(signature, msg, secretKey)
            return isValid
        } catch(e) {
            console.error
            return e
        }
    },
}

module.exports = SodiumAPI