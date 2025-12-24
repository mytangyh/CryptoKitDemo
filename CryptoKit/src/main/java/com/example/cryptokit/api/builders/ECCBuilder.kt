package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.ECCCipher
import com.example.cryptokit.core.signature.ECDSASignature
import com.example.cryptokit.exception.CryptoException
import com.example.cryptokit.exception.SignatureException
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
class ECCBuilder {
    private var curve: String = "secp256r1"
    private var signatureAlgorithm: String = "SHA256withECDSA"
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

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
                if (curve in SUPPORTED_CURVES) curve
                else throw ValidationException("Unsupported curve: $curve, supported: $SUPPORTED_CURVES")
            }
        }
    }

    fun p256(): ECCBuilder = apply { this.curve = "secp256r1" }
    fun p384(): ECCBuilder = apply { this.curve = "secp384r1" }
    fun p521(): ECCBuilder = apply { this.curve = "secp521r1" }

    fun signatureAlgorithm(algorithm: String): ECCBuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(key: PublicKey): ECCBuilder = apply { 
        validatePublicKey(key)
        this.publicKey = key 
    }

    fun publicKey(keyBytes: ByteArray): ECCBuilder = apply {
        if (keyBytes.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        try {
            val keyFactory = KeyFactory.getInstance("EC")
            this.publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
        } catch (e: Exception) {
            throw ValidationException("Invalid EC public key bytes", e)
        }
    }

    fun privateKey(key: PrivateKey): ECCBuilder = apply { 
        validatePrivateKey(key)
        this.privateKey = key 
    }

    fun privateKey(keyBytes: ByteArray): ECCBuilder = apply {
        if (keyBytes.isEmpty()) {
            throw ValidationException.emptyInput()
        }
        try {
            val keyFactory = KeyFactory.getInstance("EC")
            this.privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        } catch (e: Exception) {
            throw ValidationException("Invalid EC private key bytes", e)
        }
    }
    
    /**
     * 同时设置公钥和私钥
     */
    fun keyPair(keyPair: KeyPair): ECCBuilder = apply {
        this.publicKey = keyPair.public
        this.privateKey = keyPair.private
    }

    /**
     * 生成密钥对
     */
    fun generateKeyPair(): KeyPair {
        try {
            return cipher.generateKeyPair()
        } catch (e: Exception) {
            throw CryptoException("Failed to generate EC key pair: ${e.message}", e)
        }
    }

    /**
     * 签名
     * 
     * @throws SignatureException 签名失败时抛出
     * @throws ValidationException 输入验证失败时抛出
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
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw SignatureException.signFailed(e)
        }
    }

    fun sign(data: String): ByteArray = sign(data.toByteArray(Charsets.UTF_8))

    /**
     * 验证签名
     * 
     * @throws SignatureException 验证失败时抛出
     * @throws ValidationException 输入验证失败时抛出
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
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw SignatureException.verifyFailed(e)
        }
    }

    fun verify(data: String, signatureBytes: ByteArray): Boolean = 
        verify(data.toByteArray(Charsets.UTF_8), signatureBytes)

    /**
     * ECDH密钥协商 - 派生共享密钥
     * 
     * @throws CryptoException 密钥协商失败时抛出
     * @throws ValidationException 输入验证失败时抛出
     */
    fun deriveSharedSecret(peerPublicKey: PublicKey): ByteArray {
        if (privateKey == null) {
            throw ValidationException.nullParameter("privateKey")
        }
        validatePublicKey(peerPublicKey)
        
        try {
            return cipher.deriveSharedSecret(privateKey!!, peerPublicKey)
        } catch (e: ValidationException) {
            throw e
        } catch (e: Exception) {
            throw CryptoException("ECDH key agreement failed: ${e.message}", e)
        }
    }
    
    private fun validatePublicKey(key: PublicKey) {
        if (key.algorithm != "EC") {
            throw ValidationException("Invalid public key algorithm: ${key.algorithm}, expected: EC")
        }
    }
    
    private fun validatePrivateKey(key: PrivateKey) {
        if (key.algorithm != "EC") {
            throw ValidationException("Invalid private key algorithm: ${key.algorithm}, expected: EC")
        }
    }
    
    companion object {
        private val SUPPORTED_CURVES = listOf("secp256r1", "secp384r1", "secp521r1")
    }
}
