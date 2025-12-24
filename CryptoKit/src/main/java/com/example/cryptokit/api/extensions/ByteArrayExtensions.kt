package com.example.cryptokit.api.extensions

import android.util.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * ByteArray扩展函数
 */

/**
 * 转换为Base64字符串
 */
fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.DEFAULT)

/**
 * 转换为URL安全的Base64字符串
 */
fun ByteArray.toBase64Url(): String = Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_WRAP)

/**
 * 转换为无换行的Base64字符串
 */
fun ByteArray.toBase64NoWrap(): String = Base64.encodeToString(this, Base64.NO_WRAP)

/**
 * 转换为十六进制字符串
 */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/**
 * String扩展函数
 */

/**
 * 从Base64解码
 */
fun String.fromBase64(): ByteArray = Base64.decode(this, Base64.DEFAULT)

/**
 * 从URL安全的Base64解码
 */
fun String.fromBase64Url(): ByteArray = Base64.decode(this, Base64.URL_SAFE or Base64.NO_WRAP)

/**
 * 从十六进制解码
 */
fun String.fromHex(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/**
 * URL编码
 */
fun String.urlEncode(): String = URLEncoder.encode(this, StandardCharsets.UTF_8.toString())

/**
 * URL解码
 */
fun String.urlDecode(): String = URLDecoder.decode(this, StandardCharsets.UTF_8.toString())
