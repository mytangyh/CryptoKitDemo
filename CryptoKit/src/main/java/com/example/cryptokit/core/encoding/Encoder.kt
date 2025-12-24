package com.example.cryptokit.core.encoding

/**
 * 编码器接口
 */
interface Encoder {
    /**
     * 编码
     */
    fun encode(data: ByteArray): String

    /**
     * 解码
     */
    fun decode(encoded: String): ByteArray

    /**
     * 获取编码类型名称
     */
    val name: String
}
