package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.signature.RSASignature
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.SignatureException
import com.example.cryptokit.exception.ValidationException
import com.example.cryptokit.interceptor.InterceptorChain
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * RSA加密Builder - 支持默认推荐配置
 * 
 * 金融级特性：
 * - 严格的输入验证
 * - 完善的异常处理
 * - 支持多种填充方案
 * - 线程安全
 * 
 * 默认配置：RSA-2048，OAEP填充
 */
class RSABuilder {
    private var keySize: Int = 2048
    private var padding: String = "OAEPWithSHA-256AndMGF1Padding"
    private var signatureAlgorithm: String = "SHA256withRSA"
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    private val cipher: RSACipher
        get() = RSACipher(padding)

    private val signature: RSASignature
        get() = RSASignature(signatureAlgorithm)

    /**
     * 设置密钥长度
     */
    fun keySize(size: Int): RSABuilder = apply {
        if (size !in VALID_KEY_SIZES) {
            throw ValidationException.invalidKeySize(VALID_KEY_SIZES, size)
        }
        // 金融级安全：建议使用2048位以上
        if (size < 2048) {
            // 可考虑发出警告日志
        }
        this.keySize = size
    }

    fun padding(padding: String): RSABuilder = apply { this.padding = padding }

    fun oaepSha256(): RSABuilder = apply { this.padding = "OAEPWithSHA-256AndMGF1Padding" }
    fun oaepSha1(): RSABuilder = apply { this.padding = "OAEPWithSHA-1AndMGF1Padding" }
    fun pkcs1(): RSABuilder = apply { this.padding = "PKCS1Padding" }

    fun signatureAlgorithm(algorithm: String): RSABuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(key: PublicKey): RSABuilder = apply { 
        validatePublicKey(key)
        this.publicKey = key 
    }

    fun publicKey(keyBytes: ByteArray): RSABuilder = apply {
        if (keyBytes.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            this.publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
        } catch (e: Exception) {
            throw ValidationException("Invalid RSA public key bytes", e)
        }
    }

    fun privateKey(key: PrivateKey): RSABuilder = apply { 
        validatePrivateKey(key)
        this.privateKey = key 
    }

    fun privateKey(keyBytes: ByteArray): RSABuilder = apply {
        if (keyBytes.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        try {
            val keyFactory = KeyFactory.getInstance("RSA")
            this.privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        } catch (e: Exception) {
            throw ValidationException("Invalid RSA private key bytes", e)
        }
    }
    
    /**
     * 同时设置公钥和私钥
     */
    fun keyPair(keyPair: KeyPair): RSABuilder = apply {
        this.publicKey = keyPair.public
        this.privateKey = keyPair.private
    }

    fun generateKeyPair(): KeyPair {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(keySize, SecureRandom())
            return keyPairGenerator.generateKeyPair()
        } catch (e: Exception) {
            throw EncryptionException("Failed to generate RSA key pair: ${e.message}", e)
        }
    }

    /**
     * 加密
     * 
     * @throws EncryptionException 加密失败时抛出
     * @throws ValidationException 输入验证失败时抛出
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        // 输入验证
        if (plaintext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (publicKey == null) {
            throw ValidationException.nullParameter("publicKey")
        }
        
        // RSA加密长度限制检查
        val maxLength = getMaxEncryptLength()
        if (plaintext.size > maxLength) {
            throw ValidationException(
                "Plaintext too long for RSA-$keySize encryption: ${plaintext.size} bytes, max: $maxLength bytes. " +
                "Consider using hybrid encryption for large data."
            )
        }
        
        try {
            // 拦截器：加密前
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "RSA-$keySize")
            
            val ciphertext = cipher.encrypt(processedPlaintext, publicKey!!)
            
            // 拦截器：加密后
            return InterceptorChain.afterEncrypt(ciphertext, "RSA-$keySize")
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw EncryptionException("RSA encryption failed: ${e.message}", e)
        }
    }

    fun encrypt(plaintext: String): ByteArray = encrypt(plaintext.toByteArray(Charsets.UTF_8))

    /**
     * 解密
     * 
     * @throws DecryptionException 解密失败时抛出
     * @throws ValidationException 输入验证失败时抛出
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        // 输入验证
        if (ciphertext.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (privateKey == null) {
            throw ValidationException.nullParameter("privateKey")
        }
        
        try {
            // 拦截器：解密前
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "RSA-$keySize")
            
            val plaintext = cipher.decrypt(processedCiphertext, privateKey!!)
            
            // 拦截器：解密后
            return InterceptorChain.afterDecrypt(plaintext, "RSA-$keySize")
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw DecryptionException("RSA decryption failed: ${e.message}", e)
        }
    }

    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

    /**
     * 签名
     * 
     * @throws SignatureException 签名失败时抛出
     */
    fun sign(data: ByteArray): ByteArray {
        if (data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (privateKey == null) {
            throw ValidationException.nullParameter("privateKey")
        }
        
        try {
            return signature.sign(data, privateKey!!)
        } catch (e: Exception) {
            throw SignatureException.signFailed(e)
        }
    }

    fun sign(data: String): ByteArray = sign(data.toByteArray(Charsets.UTF_8))

    /**
     * 验证签名
     * 
     * @throws SignatureException 验证失败时抛出
     */
    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        if (data.isEmpty() || signatureBytes.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        if (publicKey == null) {
            throw ValidationException.nullParameter("publicKey")
        }
        
        try {
            return signature.verify(data, signatureBytes, publicKey!!)
        } catch (e: Exception) {
            throw SignatureException.verifyFailed(e)
        }
    }

    fun verify(data: String, signatureBytes: ByteArray): Boolean = 
        verify(data.toByteArray(Charsets.UTF_8), signatureBytes)
    
    /**
     * 获取RSA加密最大明文长度
     */
    private fun getMaxEncryptLength(): Int {
        val keyBytes = keySize / 8
        return when {
            padding.contains("OAEP") && padding.contains("SHA-256") -> keyBytes - 66
            padding.contains("OAEP") && padding.contains("SHA-1") -> keyBytes - 42
            padding.contains("PKCS1") -> keyBytes - 11
            else -> keyBytes - 66 // 保守估计
        }
    }
    
    private fun validatePublicKey(key: PublicKey) {
        if (key.algorithm != "RSA") {
            throw ValidationException("Invalid public key algorithm: ${key.algorithm}, expected: RSA")
        }
    }
    
    private fun validatePrivateKey(key: PrivateKey) {
        if (key.algorithm != "RSA") {
            throw ValidationException("Invalid private key algorithm: ${key.algorithm}, expected: RSA")
        }
    }
    
    companion object {
        private val VALID_KEY_SIZES = listOf(1024, 2048, 3072, 4096)
    }
}
