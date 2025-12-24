package com.example.cryptokit.core.encoding

import android.util.Base64

/**
 * Base64编码器实现
 */
class Base64Encoder(
    private val flags: Int = Base64.DEFAULT
) : Encoder {

    override val name: String = "Base64"

    override fun encode(data: ByteArray): String {
        return Base64.encodeToString(data, flags)
    }

    override fun decode(encoded: String): ByteArray {
        return Base64.decode(encoded, flags)
    }

    companion object {
        /**
         * 标准Base64
         */
        fun standard(): Base64Encoder = Base64Encoder(Base64.DEFAULT)

        /**
         * URL安全的Base64
         */
        fun urlSafe(): Base64Encoder = Base64Encoder(Base64.URL_SAFE or Base64.NO_WRAP)

        /**
         * 无换行的Base64
         */
        fun noWrap(): Base64Encoder = Base64Encoder(Base64.NO_WRAP)

        /**
         * MIME格式Base64
         */
        fun mime(): Base64Encoder = Base64Encoder(Base64.CRLF)
    }
}
