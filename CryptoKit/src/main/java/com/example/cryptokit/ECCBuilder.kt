package com.example.cryptokit

import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement

/**
 * ECC加密Builder - 支持ECDSA签名和ECDH密钥协商
 * 默认配置：P-256曲线
 */
class ECCBuilder {
    private var curve: String = "secp256r1"  // P-256
    private var signatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm.SHA256_WITH_ECDSA
    private var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null

    /**
     * 设置曲线（P-256/P-384/P-521）
     */
    fun curve(curve: String): ECCBuilder = apply { 
        require(curve in listOf("secp256r1", "secp384r1", "secp521r1", "P-256", "P-384", "P-521")) {
            "Curve must be P-256, P-384, or P-521"
        }
        this.curve = when(curve) {
            "P-256" -> "secp256r1"
            "P-384" -> "secp384r1"
            "P-521" -> "secp521r1"
            else -> curve
        }
    }

    /**
     * 设置签名算法
     */
    fun signatureAlgorithm(algorithm: SignatureAlgorithm): ECCBuilder = apply { 
        this.signatureAlgorithm = algorithm 
    }

    /**
     * 设置公钥
     */
    fun publicKey(key: PublicKey): ECCBuilder = apply { this.publicKey = key }

    /**
     * 从字节数组设置公钥
     */
    fun publicKey(keyBytes: ByteArray): ECCBuilder = apply {
        val keyFactory = KeyFactory.getInstance("EC")
        val keySpec = X509EncodedKeySpec(keyBytes)
        this.publicKey = keyFactory.generatePublic(keySpec)
    }

    /**
     * 设置私钥
     */
    fun privateKey(key: PrivateKey): ECCBuilder = apply { this.privateKey = key }

    /**
     * 从字节数组设置私钥
     */
    fun privateKey(keyBytes: ByteArray): ECCBuilder = apply {
        val keyFactory = KeyFactory.getInstance("EC")
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        this.privateKey = keyFactory.generatePrivate(keySpec)
    }

    /**
     * 生成密钥对
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        val ecSpec = ECGenParameterSpec(curve)
        keyPairGenerator.initialize(ecSpec, SecureRandom())
        return keyPairGenerator.generateKeyPair()
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
     * ECDH密钥协商 - 生成共享密钥
     * @param peerPublicKey 对方的公钥
     * @return 共享密钥（可用于对称加密）
     */
    fun deriveSharedSecret(peerPublicKey: PublicKey): ByteArray {
        requireNotNull(privateKey) { "Private key must be set for key agreement" }
        
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(peerPublicKey, true)
        return keyAgreement.generateSecret()
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
