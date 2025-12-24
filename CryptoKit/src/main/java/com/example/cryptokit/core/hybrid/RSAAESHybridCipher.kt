package com.example.cryptokit.core.hybrid

import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.util.SecureRandomUtil
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

/**
 * RSA+AES混合加密实现
 */
class RSAAESHybridCipher(
    private val rsaCipher: RSACipher = RSACipher.oaepSha256(),
    private val aesCipher: AESCipher = AESCipher.gcm(),
    private val aesKeySize: Int = 256
) : HybridCipher {

    override fun encrypt(plaintext: ByteArray, publicKey: PublicKey): HybridEncryptionResult {
        // 1. 生成随机AES密钥
        val aesKey = aesCipher.generateKey(aesKeySize)
        
        // 2. 生成随机IV
        val iv = aesCipher.generateIV()
        
        // 3. 使用AES加密数据
        val ciphertext = aesCipher.encrypt(plaintext, aesKey, iv)
        
        // 4. 使用RSA加密AES密钥
        val encryptedKey = rsaCipher.encrypt(aesKey.encoded, publicKey)
        
        return HybridEncryptionResult(
            encryptedKey = encryptedKey,
            ciphertext = ciphertext,
            iv = iv
        )
    }

    override fun decrypt(result: HybridEncryptionResult, privateKey: PrivateKey): ByteArray {
        // 1. 使用RSA解密AES密钥
        val aesKeyBytes = rsaCipher.decrypt(result.encryptedKey, privateKey)
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")
        
        // 2. 使用AES解密数据
        return aesCipher.decrypt(result.ciphertext, aesKey, result.iv)
    }

    companion object {
        fun default(): RSAAESHybridCipher = RSAAESHybridCipher()
    }
}
