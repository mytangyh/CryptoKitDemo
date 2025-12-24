package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.signature.RSASignature
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.interceptor.InterceptorChain
import com.example.cryptokit.util.CryptoLogger
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * # RSA 加密 Builder
 *
 * RSA 是广泛使用的非对称加密算法，支持加密/解密和数字签名。
 * 默认使用 **RSA-2048** 和 **OAEP-SHA256** 填充。
 *
 * ## 支持的配置
 *
 * | 配置项 | 可选值 | 默认值 |
 * |--------|--------|--------|
 * | 密钥长度 | 1024, 2048, 3072, 4096 位 | 2048 |
 * | 填充方案 | OAEP-SHA256, OAEP-SHA1, PKCS1 | OAEP-SHA256 |
 * | 签名算法 | SHA256withRSA 等 | SHA256withRSA |
 *
 * ## 基本用法
 *
 * ```kotlin
 * // 生成密钥对
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 *
 * // 加密
 * val ciphertext = CryptoKit.rsa()
 *     .publicKey(keyPair.public)
 *     .encrypt("Secret message")
 *
 * // 解密
 * val plaintext = CryptoKit.rsa()
 *     .privateKey(keyPair.private)
 *     .decryptToString(ciphertext)
 * ```
 *
 * ## 数字签名
 *
 * ```kotlin
 * // 签名
 * val signature = CryptoKit.rsa()
 *     .privateKey(keyPair.private)
 *     .sign("data to sign")
 *
 * // 验证
 * val isValid = CryptoKit.rsa()
 *     .publicKey(keyPair.public)
 *     .verify("data to sign", signature)
 * ```
 *
 * ## 安全建议
 *
 * - **密钥长度至少 2048 位**：1024 位已不安全
 * - **使用 OAEP 填充**：比 PKCS1 更安全
 * - **大数据使用混合加密**：RSA 有长度限制，请使用 [HybridBuilder]
 * - **私钥安全存储**：使用 Android Keystore
 *
 * ## 明文长度限制
 *
 * RSA 加密有明文长度限制，取决于密钥长度和填充方案：
 *
 * | 密钥长度 | OAEP-SHA256 | PKCS1 |
 * |----------|-------------|-------|
 * | 2048 位 | 190 字节 | 245 字节 |
 * | 4096 位 | 446 字节 | 501 字节 |
 *
 * 如需加密更长数据，请使用 [HybridBuilder]。
 *
 * @since 1.0.0
 * @see HybridBuilder
 * @see com.example.cryptokit.CryptoKit.rsa
 */
class RSABuilder : AsymmetricBuilder<RSABuilder>() {
    
    override fun self(): RSABuilder = this
    override fun expectedKeyAlgorithm(): String = "RSA"
    
    private var keySize: Int = 2048
    private var padding: String = "OAEPWithSHA-256AndMGF1Padding"
    private var signatureAlgorithm: String = "SHA256withRSA"

    private val cipher: RSACipher
        get() = RSACipher(padding)

    private val signature: RSASignature
        get() = RSASignature(signatureAlgorithm)

    /**
     * 设置密钥长度
     *
     * @param size 密钥长度（位）：1024, 2048, 3072, 4096
     * @return this
     * @throws ValidationException 无效的密钥长度
     */
    fun keySize(size: Int): RSABuilder = apply {
        requireIn(size, VALID_KEY_SIZES, "keySize")
        this.keySize = size
    }

    /**
     * 设置填充方案
     *
     * @param padding 填充方案
     * @return this
     */
    fun padding(padding: String): RSABuilder = apply { this.padding = padding }

    /**
     * 使用 OAEP-SHA256 填充（默认推荐）
     *
     * @return this
     */
    fun oaepSha256(): RSABuilder = apply { this.padding = "OAEPWithSHA-256AndMGF1Padding" }
    
    /**
     * 使用 OAEP-SHA1 填充
     *
     * @return this
     */
    fun oaepSha1(): RSABuilder = apply { this.padding = "OAEPWithSHA-1AndMGF1Padding" }
    
    /**
     * 使用 PKCS1 填充
     *
     * **注意**: PKCS1 填充安全性较低，建议使用 OAEP。
     *
     * @return this
     */
    fun pkcs1(): RSABuilder = apply { this.padding = "PKCS1Padding" }

    /**
     * 设置签名算法
     *
     * @param algorithm 签名算法，如 "SHA256withRSA"
     * @return this
     */
    fun signatureAlgorithm(algorithm: String): RSABuilder = apply { this.signatureAlgorithm = algorithm }

    /**
     * 从字节数组设置公钥
     *
     * @param keyBytes X.509 编码的公钥字节数组
     * @return this
     * @throws ValidationException 无效的公钥
     */
    fun publicKey(keyBytes: ByteArray): RSABuilder = apply {
        requireNotEmpty(keyBytes, "publicKeyBytes")
        val key = wrapCryptoException("Parse public key") {
            val keyFactory = KeyFactory.getInstance("RSA")
            keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
        }
        this.publicKey = key
    }

    /**
     * 从字节数组设置私钥
     *
     * @param keyBytes PKCS#8 编码的私钥字节数组
     * @return this
     * @throws ValidationException 无效的私钥
     */
    fun privateKey(keyBytes: ByteArray): RSABuilder = apply {
        requireNotEmpty(keyBytes, "privateKeyBytes")
        val key = wrapCryptoException("Parse private key") {
            val keyFactory = KeyFactory.getInstance("RSA")
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        }
        this.privateKey = key
    }

    /**
     * 生成 RSA 密钥对
     *
     * @return 新生成的密钥对
     * @throws com.example.cryptokit.exception.CryptoException 生成失败
     */
    fun generateKeyPair(): KeyPair = wrapCryptoException("Generate RSA key pair") {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        keyPairGenerator.generateKeyPair()
    }

    /**
     * 加密字节数组
     *
     * 必须先设置公钥。
     *
     * @param plaintext 明文
     * @return 密文
     * @throws com.example.cryptokit.exception.EncryptionException 加密失败
     * @throws ValidationException 明文过长或公钥未设置
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        requireNotEmpty(plaintext, "plaintext")
        val key = requirePublicKey()
        
        val maxLength = getMaxEncryptLength()
        if (plaintext.size > maxLength) {
            CryptoLogger.logSecurityWarning("RSA", "Plaintext too long: ${plaintext.size}B, max: ${maxLength}B")
            throw ValidationException(
                "Plaintext too long for RSA-$keySize encryption: ${plaintext.size} bytes, max: $maxLength bytes. " +
                "Consider using hybrid encryption for large data."
            )
        }
        
        val startTime = System.currentTimeMillis()
        CryptoLogger.logEncrypt("RSA-$keySize", plaintext.size, keySize)
        
        return wrapEncryptionException("RSA-$keySize") {
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "RSA-$keySize")
            val ciphertext = cipher.encrypt(processedPlaintext, key)
            
            val duration = System.currentTimeMillis() - startTime
            CryptoLogger.logEncryptComplete("RSA-$keySize", plaintext.size, ciphertext.size, duration)
            
            InterceptorChain.afterEncrypt(ciphertext, "RSA-$keySize")
        }
    }

    /**
     * 加密字符串
     *
     * @param plaintext UTF-8 明文字符串
     * @return 密文
     */
    fun encrypt(plaintext: String): ByteArray = encrypt(plaintext.toByteArray(Charsets.UTF_8))

    /**
     * 解密字节数组
     *
     * 必须先设置私钥。
     *
     * @param ciphertext 密文
     * @return 明文
     * @throws com.example.cryptokit.exception.DecryptionException 解密失败
     * @throws ValidationException 私钥未设置
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotEmpty(ciphertext, "ciphertext")
        val key = requirePrivateKey()
        
        val startTime = System.currentTimeMillis()
        CryptoLogger.logDecrypt("RSA-$keySize", ciphertext.size)
        
        return wrapDecryptionException("RSA-$keySize") {
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "RSA-$keySize")
            val plaintext = cipher.decrypt(processedCiphertext, key)
            
            val duration = System.currentTimeMillis() - startTime
            CryptoLogger.logDecryptComplete("RSA-$keySize", ciphertext.size, plaintext.size, duration)
            
            InterceptorChain.afterDecrypt(plaintext, "RSA-$keySize")
        }
    }

    /**
     * 解密并返回字符串
     *
     * @param ciphertext 密文
     * @return UTF-8 明文字符串
     */
    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

    /**
     * 数字签名
     *
     * 必须先设置私钥。
     *
     * @param data 要签名的数据
     * @return 签名字节数组
     * @throws com.example.cryptokit.exception.SignatureException 签名失败
     */
    fun sign(data: ByteArray): ByteArray {
        requireNotEmpty(data, "data")
        val key = requirePrivateKey()
        
        CryptoLogger.logSign("RSA-$signatureAlgorithm", data.size)
        val sig = wrapSignatureException("sign") { signature.sign(data, key) }
        CryptoLogger.i("Sign", "[RSA] Signature created: ${sig.size} bytes")
        return sig
    }

    /**
     * 对字符串签名
     *
     * @param data UTF-8 字符串
     * @return 签名字节数组
     */
    fun sign(data: String): ByteArray = sign(data.toByteArray(Charsets.UTF_8))

    /**
     * 验证签名
     *
     * 必须先设置公钥。
     *
     * @param data 原始数据
     * @param signatureBytes 签名
     * @return 签名是否有效
     * @throws com.example.cryptokit.exception.SignatureException 验证过程中发生错误
     */
    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        requireNotEmpty(data, "data")
        requireNotEmpty(signatureBytes, "signature")
        val key = requirePublicKey()
        
        val result = wrapSignatureException("verify") { signature.verify(data, signatureBytes, key) }
        CryptoLogger.logVerify("RSA-$signatureAlgorithm", data.size, result)
        return result
    }

    /**
     * 验证字符串签名
     *
     * @param data UTF-8 字符串
     * @param signatureBytes 签名
     * @return 签名是否有效
     */
    fun verify(data: String, signatureBytes: ByteArray): Boolean = 
        verify(data.toByteArray(Charsets.UTF_8), signatureBytes)
    
    /**
     * 获取当前配置下的最大明文长度
     *
     * @return 最大明文字节数
     */
    private fun getMaxEncryptLength(): Int {
        val keyBytes = keySize / 8
        return when {
            padding.contains("OAEP") && padding.contains("SHA-256") -> keyBytes - 66
            padding.contains("OAEP") && padding.contains("SHA-1") -> keyBytes - 42
            padding.contains("PKCS1") -> keyBytes - 11
            else -> keyBytes - 66
        }
    }
    
    companion object {
        private val VALID_KEY_SIZES = listOf(1024, 2048, 3072, 4096)
    }
}
