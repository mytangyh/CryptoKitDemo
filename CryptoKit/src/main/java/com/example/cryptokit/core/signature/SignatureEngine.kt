package com.example.cryptokit.core.signature

import java.security.PrivateKey
import java.security.PublicKey

/**
 * 数字签名接口
 */
interface SignatureEngine {
    /**
     * 签名
     */
    fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray

    /**
     * 验签
     */
    fun verify(data: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean

    /**
     * 获取算法名称
     */
    val algorithmName: String
}
