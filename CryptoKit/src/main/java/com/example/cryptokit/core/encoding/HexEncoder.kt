package com.example.cryptokit.core.encoding

/**
 * Hex编码器实现
 */
class HexEncoder : Encoder {

    override val name: String = "Hex"

    override fun encode(data: ByteArray): String {
        return data.joinToString("") { "%02x".format(it) }
    }

    override fun decode(encoded: String): ByteArray {
        check(encoded.length % 2 == 0) { "Hex string must have even length" }
        return encoded.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    companion object {
        private val instance = HexEncoder()
        fun getInstance(): HexEncoder = instance
    }
}
