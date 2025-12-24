package com.example.cryptokit.util

import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * 密钥工具类
 */
object KeyUtils {

    /**
     * 从字节数组创建AES密钥
     */
    fun createAESKey(keyBytes: ByteArray): SecretKey {
        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * 从字节数组创建3DES密钥
     */
    fun createTripleDESKey(keyBytes: ByteArray): SecretKey {
        return SecretKeySpec(keyBytes, "DESede")
    }

    /**
     * 从编码字节创建RSA公钥
     */
    fun createRSAPublicKey(encoded: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(X509EncodedKeySpec(encoded))
    }

    /**
     * 从编码字节创建RSA私钥
     */
    fun createRSAPrivateKey(encoded: ByteArray): PrivateKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    /**
     * 从编码字节创建EC公钥
     */
    fun createECPublicKey(encoded: ByteArray): PublicKey {
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(X509EncodedKeySpec(encoded))
    }

    /**
     * 从编码字节创建EC私钥
     */
    fun createECPrivateKey(encoded: ByteArray): PrivateKey {
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    /**
     * 导出公钥为字节数组
     */
    fun exportPublicKey(publicKey: PublicKey): ByteArray = publicKey.encoded

    /**
     * 导出私钥为字节数组
     */
    fun exportPrivateKey(privateKey: PrivateKey): ByteArray = privateKey.encoded

    /**
     * 导出密钥为字节数组
     */
    fun exportSecretKey(secretKey: SecretKey): ByteArray = secretKey.encoded

    /**
     * 清除敏感数据
     */
    fun clearBytes(bytes: ByteArray) {
        bytes.fill(0)
    }
}
