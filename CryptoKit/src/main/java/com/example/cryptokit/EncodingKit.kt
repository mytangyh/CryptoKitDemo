package com.example.cryptokit

import android.util.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * 编码工具类
 */
object EncodingKit {

    // ==================== Base64 ====================

    /**
     * 将字节数组编码为Base64字符串
     */
    fun toBase64(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.DEFAULT)
    }

    /**
     * 将字节数组编码为URL安全的Base64字符串
     */
    fun toBase64Url(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    /**
     * 将字节数组编码为无换行的Base64字符串
     */
    fun toBase64NoWrap(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP)
    }

    /**
     * 将Base64字符串解码为字节数组
     */
    fun fromBase64(encoded: String): ByteArray {
        return Base64.decode(encoded, Base64.DEFAULT)
    }

    /**
     * 将URL安全的Base64字符串解码为字节数组
     */
    fun fromBase64Url(encoded: String): ByteArray {
        return Base64.decode(encoded, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    // ==================== Hex ====================

    /**
     * 将字节数组编码为十六进制字符串
     */
    fun toHex(data: ByteArray): String {
        return data.joinToString("") { "%02x".format(it) }
    }

    /**
     * 将十六进制字符串解码为字节数组
     */
    fun fromHex(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "Hex string must have even length" }
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    // ==================== URL编码 ====================

    /**
     * URL编码
     */
    fun urlEncode(text: String): String {
        return URLEncoder.encode(text, StandardCharsets.UTF_8.toString())
    }

    /**
     * URL解码
     */
    fun urlDecode(encoded: String): String {
        return URLDecoder.decode(encoded, StandardCharsets.UTF_8.toString())
    }
}

// ==================== 扩展函数 ====================

/**
 * ByteArray扩展：转换为Base64字符串
 */
fun ByteArray.toBase64(): String = EncodingKit.toBase64(this)

/**
 * ByteArray扩展：转换为URL安全的Base64字符串
 */
fun ByteArray.toBase64Url(): String = EncodingKit.toBase64Url(this)

/**
 * ByteArray扩展：转换为无换行的Base64字符串
 */
fun ByteArray.toBase64NoWrap(): String = EncodingKit.toBase64NoWrap(this)

/**
 * ByteArray扩展：转换为十六进制字符串
 */
fun ByteArray.toHex(): String = EncodingKit.toHex(this)

/**
 * String扩展：从Base64解码
 */
fun String.fromBase64(): ByteArray = EncodingKit.fromBase64(this)

/**
 * String扩展：从URL安全的Base64解码
 */
fun String.fromBase64Url(): ByteArray = EncodingKit.fromBase64Url(this)

/**
 * String扩展：从十六进制解码
 */
fun String.fromHex(): ByteArray = EncodingKit.fromHex(this)

/**
 * String扩展：URL编码
 */
fun String.urlEncode(): String = EncodingKit.urlEncode(this)

/**
 * String扩展：URL解码
 */
fun String.urlDecode(): String = EncodingKit.urlDecode(this)
