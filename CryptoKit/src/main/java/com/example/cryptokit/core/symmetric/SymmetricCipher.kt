package com.example.cryptokit.core.symmetric

import javax.crypto.SecretKey

/**
 * 对称加密接口
 */
interface SymmetricCipher {
    /**
     * 加密
     */
    fun encrypt(plaintext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray

    /**
     * 解密
     */
    fun decrypt(ciphertext: ByteArray, key: SecretKey, iv: ByteArray): ByteArray

    /**
     * 生成密钥
     */
    fun generateKey(keySize: Int = defaultKeySize): SecretKey

    /**
     * 生成IV
     */
    fun generateIV(): ByteArray

    /**
     * 获取算法名称
     */
    val algorithmName: String

    /**
     * 获取默认密钥大小（位）
     */
    val defaultKeySize: Int

    /**
     * 获取IV大小（字节）
     */
    val ivSize: Int
}
