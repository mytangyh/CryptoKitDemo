package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.ECCCipher
import com.example.cryptokit.core.signature.ECDSASignature
import com.example.cryptokit.exception.ValidationException
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * ECC加密Builder - 支持ECDSA签名和ECDH密钥协商
 * 
 * 金融级特性：
 * - 严格的输入验证
 * - 类型化异常处理
 * - 支持多种曲线
 * 
 * 默认配置：P-256曲线
 */
class ECCBuilder : AsymmetricBuilder<ECCBuilder>() {
    
    override fun self(): ECCBuilder = this
    override fun expectedKeyAlgorithm(): String = "EC"
    
    private var curve: String = "secp256r1"
    private var signatureAlgorithm: String = "SHA256withECDSA"

    private val cipher: ECCCipher
        get() = ECCCipher(curve)

    private val signature: ECDSASignature
        get() = ECDSASignature(signatureAlgorithm)

    /**
     * 设置曲线
     */
    fun curve(curve: String): ECCBuilder = apply {
        this.curve = when (curve.uppercase()) {
            "P-256", "SECP256R1" -> "secp256r1"
            "P-384", "SECP384R1" -> "secp384r1"
            "P-521", "SECP521R1" -> "secp521r1"
            else -> {
                requireIn(curve, SUPPORTED_CURVES, "curve")
                curve
            }
        }
    }

    fun p256(): ECCBuilder = apply { this.curve = "secp256r1" }
    fun p384(): ECCBuilder = apply { this.curve = "secp384r1" }
    fun p521(): ECCBuilder = apply { this.curve = "secp521r1" }

    fun signatureAlgorithm(algorithm: String): ECCBuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(keyBytes: ByteArray): ECCBuilder = apply {
        requireNotEmpty(keyBytes, "publicKeyBytes")
        val key = wrapCryptoException("Parse EC public key") {
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
        }
        this.publicKey = key
    }

    fun privateKey(keyBytes: ByteArray): ECCBuilder = apply {
        requireNotEmpty(keyBytes, "privateKeyBytes")
        val key = wrapCryptoException("Parse EC private key") {
            val keyFactory = KeyFactory.getInstance("EC")
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        }
        this.privateKey = key
    }

    /**
     * 生成密钥对
     */
    fun generateKeyPair(): KeyPair = wrapCryptoException("Generate EC key pair") {
        cipher.generateKeyPair()
    }

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

    /**
     * ECDH密钥协商 - 派生共享密钥
     */
    fun deriveSharedSecret(peerPublicKey: PublicKey): ByteArray {
        val key = requirePrivateKey()
        validatePublicKey(peerPublicKey)
        return wrapCryptoException("ECDH key agreement") {
            cipher.deriveSharedSecret(key, peerPublicKey)
        }
    }
    
    companion object {
        private val SUPPORTED_CURVES = listOf("secp256r1", "secp384r1", "secp521r1")
    }
}
