package com.example.cryptokit.core.asymmetric

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

/**
 * 非对称加密接口
 */
interface AsymmetricCipher {
    /**
     * 使用公钥加密
     */
    fun encrypt(plaintext: ByteArray, publicKey: PublicKey): ByteArray

    /**
     * 使用私钥解密
     */
    fun decrypt(ciphertext: ByteArray, privateKey: PrivateKey): ByteArray

    /**
     * 生成密钥对
     */
    fun generateKeyPair(keySize: Int = defaultKeySize): KeyPair

    /**
     * 获取算法名称
     */
    val algorithmName: String

    /**
     * 获取默认密钥大小（位）
     */
    val defaultKeySize: Int
}
