package com.example.cryptokit

import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * RSA加密Builder - 支持默认推荐配置
 * 默认配置：RSA-2048，OAEP填充
 */
class RSABuilder {
    private var keySize: Int = 2048
    private var padding: RSAPadding = RSAPadding.OAEP_SHA256
    private var signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256_WITH_RSA
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    /**
     * 设置密钥长度
     */
    fun keySize(size: Int): RSABuilder = apply { 
        require(size in listOf(1024, 2048, 4096)) { "RSA key size must be 1024, 2048, or 4096 bits" }
        this.keySize = size 
    }

    /**
     * 设置填充方案
     */
    fun padding(padding: RSAPadding): RSABuilder = apply { this.padding = padding }

    /**
     * 设置签名算法
     */
    fun signatureAlgorithm(algorithm: SignatureAlgorithm): RSABuilder = apply { 
        this.signatureAlgorithm = algorithm 
    }

    /**
     * 设置公钥
     */
    fun publicKey(key: PublicKey): RSABuilder = apply { this.publicKey = key }

    /**
     * 从字节数组设置公钥
     */
    fun publicKey(keyBytes: ByteArray): RSABuilder = apply {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(keyBytes)
        this.publicKey = keyFactory.generatePublic(keySpec)
    }

    /**
     * 设置私钥
     */
    fun privateKey(key: PrivateKey): RSABuilder = apply { this.privateKey = key }

    /**
     * 从字节数组设置私钥
     */
    fun privateKey(keyBytes: ByteArray): RSABuilder = apply {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        this.privateKey = keyFactory.generatePrivate(keySpec)
    }

    /**
     * 生成密钥对
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * 使用公钥加密
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        requireNotNull(publicKey) { "Public key must be set for encryption" }
        
        val transformation = "RSA/ECB/${padding.paddingName}"
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(plaintext)
    }

    /**
     * 加密字符串
     */
    fun encrypt(plaintext: String): ByteArray {
        return encrypt(plaintext.toByteArray(Charsets.UTF_8))
    }

    /**
     * 使用私钥解密
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for decryption" }
        
        val transformation = "RSA/ECB/${padding.paddingName}"
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(ciphertext)
    }

    /**
     * 解密并返回字符串
     */
    fun decryptToString(ciphertext: ByteArray): String {
        return String(decrypt(ciphertext), Charsets.UTF_8)
    }

    /**
     * 使用私钥签名
     */
    fun sign(data: ByteArray): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for signing" }
        
        val signature = Signature.getInstance(signatureAlgorithm.algorithmName)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    /**
     * 对字符串签名
     */
    fun sign(data: String): ByteArray {
        return sign(data.toByteArray(Charsets.UTF_8))
    }

    /**
     * 使用公钥验证签名
     */
    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        requireNotNull(publicKey) { "Public key must be set for verification" }
        
        val signature = Signature.getInstance(signatureAlgorithm.algorithmName)
        signature.initVerify(publicKey)
        signature.update(data)
        return signature.verify(signatureBytes)
    }

    /**
     * 验证字符串签名
     */
    fun verify(data: String, signatureBytes: ByteArray): Boolean {
        return verify(data.toByteArray(Charsets.UTF_8), signatureBytes)
    }

    /**
     * 导出公钥为字节数组
     */
    fun exportPublicKey(): ByteArray {
        requireNotNull(publicKey) { "Public key must be set" }
        return publicKey!!.encoded
    }

    /**
     * 导出私钥为字节数组
     */
    fun exportPrivateKey(): ByteArray {
        requireNotNull(privateKey) { "Private key must be set" }
        return privateKey!!.encoded
    }
}
