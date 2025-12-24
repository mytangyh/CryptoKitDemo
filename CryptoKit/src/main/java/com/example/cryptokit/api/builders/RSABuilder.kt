package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.signature.RSASignature
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
     */
    fun keySize(size: Int): RSABuilder = apply {
        requireIn(size, VALID_KEY_SIZES, "keySize")
        this.keySize = size
    }

    fun padding(padding: String): RSABuilder = apply { this.padding = padding }

    fun oaepSha256(): RSABuilder = apply { this.padding = "OAEPWithSHA-256AndMGF1Padding" }
    fun oaepSha1(): RSABuilder = apply { this.padding = "OAEPWithSHA-1AndMGF1Padding" }
    fun pkcs1(): RSABuilder = apply { this.padding = "PKCS1Padding" }

    fun signatureAlgorithm(algorithm: String): RSABuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(keyBytes: ByteArray): RSABuilder = apply {
        requireNotEmpty(keyBytes, "publicKeyBytes")
        val key = wrapCryptoException("Parse public key") {
            val keyFactory = KeyFactory.getInstance("RSA")
            keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
        }
        this.publicKey = key
    }

    fun privateKey(keyBytes: ByteArray): RSABuilder = apply {
        requireNotEmpty(keyBytes, "privateKeyBytes")
        val key = wrapCryptoException("Parse private key") {
            val keyFactory = KeyFactory.getInstance("RSA")
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        }
        this.privateKey = key
    }

    fun generateKeyPair(): KeyPair = wrapCryptoException("Generate RSA key pair") {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        keyPairGenerator.generateKeyPair()
    }

    /**
     * 加密
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        requireNotEmpty(plaintext, "plaintext")
        val key = requirePublicKey()
        
        // RSA加密长度限制检查
        val maxLength = getMaxEncryptLength()
        if (plaintext.size > maxLength) {
            throw ValidationException(
                "Plaintext too long for RSA-$keySize encryption: ${plaintext.size} bytes, max: $maxLength bytes. " +
                "Consider using hybrid encryption for large data."
            )
        }
        
        return wrapEncryptionException("RSA-$keySize") {
            val processedPlaintext = InterceptorChain.beforeEncrypt(plaintext, "RSA-$keySize")
            val ciphertext = cipher.encrypt(processedPlaintext, key)
            InterceptorChain.afterEncrypt(ciphertext, "RSA-$keySize")
        }
    }

    fun encrypt(plaintext: String): ByteArray = encrypt(plaintext.toByteArray(Charsets.UTF_8))

    /**
     * 解密
     */
    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotEmpty(ciphertext, "ciphertext")
        val key = requirePrivateKey()
        
        return wrapDecryptionException("RSA-$keySize") {
            val processedCiphertext = InterceptorChain.beforeDecrypt(ciphertext, "RSA-$keySize")
            val plaintext = cipher.decrypt(processedCiphertext, key)
            InterceptorChain.afterDecrypt(plaintext, "RSA-$keySize")
        }
    }

    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

    /**
     * 签名
     */
    fun sign(data: ByteArray): ByteArray {
        requireNotEmpty(data, "data")
        val key = requirePrivateKey()
        return wrapSignatureException("sign") { signature.sign(data, key) }
    }

    fun sign(data: String): ByteArray = sign(data.toByteArray(Charsets.UTF_8))

    /**
     * 验证签名
     */
    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        requireNotEmpty(data, "data")
        requireNotEmpty(signatureBytes, "signature")
        val key = requirePublicKey()
        return wrapSignatureException("verify") { signature.verify(data, signatureBytes, key) }
    }

    fun verify(data: String, signatureBytes: ByteArray): Boolean = 
        verify(data.toByteArray(Charsets.UTF_8), signatureBytes)
    
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
