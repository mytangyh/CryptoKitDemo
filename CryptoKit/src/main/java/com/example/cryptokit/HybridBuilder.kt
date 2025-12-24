package com.example.cryptokit

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 混合加密Builder - RSA+AES混合加密
 * 适用于加密大量数据的场景
 */
class HybridBuilder {
    private var symmetricAlgorithm: SymmetricAlgorithm = SymmetricAlgorithm.AES_256
    private var asymmetricAlgorithm: AsymmetricAlgorithm = AsymmetricAlgorithm.RSA_2048
    private var rsaPadding: RSAPadding = RSAPadding.OAEP_SHA256
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    /**
     * 设置对称加密算法
     */
    fun symmetricAlgorithm(algorithm: SymmetricAlgorithm): HybridBuilder = apply {
        this.symmetricAlgorithm = algorithm
    }

    /**
     * 设置非对称加密算法
     */
    fun asymmetricAlgorithm(algorithm: AsymmetricAlgorithm): HybridBuilder = apply {
        this.asymmetricAlgorithm = algorithm
    }

    /**
     * 设置RSA填充方案
     */
    fun rsaPadding(padding: RSAPadding): HybridBuilder = apply {
        this.rsaPadding = padding
    }

    /**
     * 设置公钥（用于加密）
     */
    fun publicKey(key: PublicKey): HybridBuilder = apply { this.publicKey = key }

    /**
     * 设置私钥（用于解密）
     */
    fun privateKey(key: PrivateKey): HybridBuilder = apply { this.privateKey = key }

    /**
     * 混合加密
     * 1. 生成随机AES密钥
     * 2. 使用AES-GCM加密数据
     * 3. 使用RSA加密AES密钥
     */
    fun encrypt(plaintext: ByteArray): HybridCipherResult {
        requireNotNull(publicKey) { "Public key must be set for encryption" }

        // 1. 生成随机AES密钥
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(symmetricAlgorithm.defaultKeySize, SecureRandom())
        val aesKey = keyGenerator.generateKey()

        // 2. 生成随机IV (12 bytes for GCM)
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        // 3. 使用AES-GCM加密数据
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, iv)
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)
        val ciphertext = aesCipher.doFinal(plaintext)

        // 4. 使用RSA加密AES密钥
        val rsaCipher = Cipher.getInstance("RSA/ECB/${rsaPadding.paddingName}")
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedKey = rsaCipher.doFinal(aesKey.encoded)

        return HybridCipherResult(
            encryptedKey = encryptedKey,
            ciphertext = ciphertext,
            iv = iv,
            symmetricAlgorithm = symmetricAlgorithm,
            asymmetricAlgorithm = asymmetricAlgorithm
        )
    }

    /**
     * 加密字符串
     */
    fun encrypt(plaintext: String): HybridCipherResult {
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 混合解密
     * 1. 使用RSA解密AES密钥
     * 2. 使用AES-GCM解密数据
     */
    fun decrypt(result: HybridCipherResult): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for decryption" }

        // 1. 使用RSA解密AES密钥
        val rsaCipher = Cipher.getInstance("RSA/ECB/${rsaPadding.paddingName}")
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey)
        val aesKeyBytes = rsaCipher.doFinal(result.encryptedKey)
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")

        // 2. 使用AES-GCM解密数据
        val aesCipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(128, result.iv)
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
        return aesCipher.doFinal(result.ciphertext)
    }

    /**
     * 解密并返回字符串
     */
    fun decryptToString(result: HybridCipherResult): String {
        return String(decrypt(result), Charsets.UTF_8)
    }
}
