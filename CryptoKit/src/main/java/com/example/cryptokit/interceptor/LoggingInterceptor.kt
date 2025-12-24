package com.example.cryptokit.interceptor

import android.util.Log

/**
 * 日志拦截器实现
 */
class LoggingInterceptor(
    private val tag: String = "CryptoKit",
    override val priority: Int = 100
) : CryptoInterceptor {

    override val name: String = "LoggingInterceptor"

    override fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        Log.d(tag, "[$algorithm] Encrypting ${plaintext.size} bytes")
        return plaintext
    }

    override fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        Log.d(tag, "[$algorithm] Encrypted to ${ciphertext.size} bytes")
        return ciphertext
    }

    override fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        Log.d(tag, "[$algorithm] Decrypting ${ciphertext.size} bytes")
        return ciphertext
    }

    override fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        Log.d(tag, "[$algorithm] Decrypted to ${plaintext.size} bytes")
        return plaintext
    }
}
