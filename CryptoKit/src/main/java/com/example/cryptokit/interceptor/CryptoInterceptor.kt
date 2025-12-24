package com.example.cryptokit.interceptor

/**
 * 加密拦截器接口
 */
interface CryptoInterceptor {
    /**
     * 加密前回调
     */
    fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray

    /**
     * 加密后回调
     */
    fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray

    /**
     * 解密前回调
     */
    fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray

    /**
     * 解密后回调
     */
    fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray

    /**
     * 获取拦截器名称
     */
    val name: String

    /**
     * 获取优先级（数值越小优先级越高）
     */
    val priority: Int get() = 0
}
