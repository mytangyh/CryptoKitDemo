package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.ECCCipher
import com.example.cryptokit.core.signature.ECDSASignature
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * ECC加密Builder - 支持ECDSA签名和ECDH密钥协商
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

    fun curve(curve: String): ECCBuilder = apply {
        this.curve = when (curve) {
            "P-256" -> "secp256r1"
            "P-384" -> "secp384r1"
            "P-521" -> "secp521r1"
            else -> curve
        }
    }

    fun p256(): ECCBuilder = apply { this.curve = "secp256r1" }
    fun p384(): ECCBuilder = apply { this.curve = "secp384r1" }
    fun p521(): ECCBuilder = apply { this.curve = "secp521r1" }

    fun signatureAlgorithm(algorithm: String): ECCBuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(key: PublicKey): ECCBuilder = apply { this.publicKey = key }

    fun publicKey(keyBytes: ByteArray): ECCBuilder = apply {
        val keyFactory = KeyFactory.getInstance("EC")
        this.publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    fun privateKey(key: PrivateKey): ECCBuilder = apply { this.privateKey = key }

    fun privateKey(keyBytes: ByteArray): ECCBuilder = apply {
        val keyFactory = KeyFactory.getInstance("EC")
        this.privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    fun generateKeyPair(): KeyPair = cipher.generateKeyPair()

    fun sign(data: ByteArray): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for signing" }
        return signature.sign(data, privateKey!!)
    }

    fun sign(data: String): ByteArray = sign(data.toByteArray(Charsets.UTF_8))

    fun verify(data: ByteArray, signatureBytes: ByteArray): Boolean {
        requireNotNull(publicKey) { "Public key must be set for verification" }
        return signature.verify(data, signatureBytes, publicKey!!)
    }

    fun verify(data: String, signatureBytes: ByteArray): Boolean = 
        verify(data.toByteArray(Charsets.UTF_8), signatureBytes)

    fun deriveSharedSecret(peerPublicKey: PublicKey): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for key agreement" }
        return cipher.deriveSharedSecret(privateKey!!, peerPublicKey)
    }
}
