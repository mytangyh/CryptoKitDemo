package com.example.cryptokit.api.builders

import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.signature.RSASignature
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * RSA加密Builder - 支持默认推荐配置
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

    fun keySize(size: Int): RSABuilder = apply {
        require(size in listOf(1024, 2048, 4096)) { "RSA key size must be 1024, 2048, or 4096 bits" }
        this.keySize = size
    }

    fun padding(padding: String): RSABuilder = apply { this.padding = padding }

    fun oaepSha256(): RSABuilder = apply { this.padding = "OAEPWithSHA-256AndMGF1Padding" }
    fun oaepSha1(): RSABuilder = apply { this.padding = "OAEPWithSHA-1AndMGF1Padding" }
    fun pkcs1(): RSABuilder = apply { this.padding = "PKCS1Padding" }

    fun signatureAlgorithm(algorithm: String): RSABuilder = apply { this.signatureAlgorithm = algorithm }

    fun publicKey(key: PublicKey): RSABuilder = apply { this.publicKey = key }

    fun publicKey(keyBytes: ByteArray): RSABuilder = apply {
        val keyFactory = KeyFactory.getInstance("RSA")
        this.publicKey = keyFactory.generatePublic(X509EncodedKeySpec(keyBytes))
    }

    fun privateKey(key: PrivateKey): RSABuilder = apply { this.privateKey = key }

    fun privateKey(keyBytes: ByteArray): RSABuilder = apply {
        val keyFactory = KeyFactory.getInstance("RSA")
        this.privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        requireNotNull(publicKey) { "Public key must be set for encryption" }
        return cipher.encrypt(plaintext, publicKey!!)
    }

    fun encrypt(plaintext: String): ByteArray = encrypt(plaintext.toByteArray(Charsets.UTF_8))

    fun decrypt(ciphertext: ByteArray): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for decryption" }
        return cipher.decrypt(ciphertext, privateKey!!)
    }

    fun decryptToString(ciphertext: ByteArray): String = String(decrypt(ciphertext), Charsets.UTF_8)

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
}
