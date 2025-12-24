package com.example.cryptokit.util

import java.security.SecureRandom

/**
 * 安全随机数工具类
 */
object SecureRandomUtil {
    private val secureRandom = SecureRandom()

    /**
     * 生成随机字节数组
     */
    fun nextBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * 生成IV（初始化向量）
     * @param size IV长度（字节）
     */
    fun generateIV(size: Int = 16): ByteArray = nextBytes(size)

    /**
     * 生成GCM模式的IV（12字节）
     */
    fun generateGCMIV(): ByteArray = nextBytes(12)

    /**
     * 生成盐值
     * @param size 盐值长度（字节）
     */
    fun generateSalt(size: Int = 16): ByteArray = nextBytes(size)

    /**
     * 生成随机密钥字节
     * @param keySize 密钥长度（位）
     */
    fun generateKeyBytes(keySize: Int): ByteArray = nextBytes(keySize / 8)
}
