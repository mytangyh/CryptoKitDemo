package com.example.cryptokit.core.hash

import java.io.InputStream
import javax.crypto.SecretKey

/**
 * 哈希引擎接口
 */
interface HashEngine {
    /**
     * 计算哈希
     */
    fun hash(data: ByteArray): ByteArray

    /**
     * 计算HMAC
     */
    fun hmac(data: ByteArray, key: ByteArray): ByteArray

    /**
     * 流式哈希
     */
    fun hashStream(inputStream: InputStream): ByteArray

    /**
     * 派生密钥
     */
    fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int
    ): SecretKey

    /**
     * 获取算法名称
     */
    val algorithmName: String

    /**
     * 获取摘要长度（字节）
     */
    val digestLength: Int
}
