package com.example.cryptokit.interceptor

import com.example.cryptokit.util.CryptoLogger

/**
 * 日志拦截器实现
 * 
 * 基于拦截器链的日志记录，在加密/解密操作的进入和退出点记录日志。
 * 内部复用 [CryptoLogger] 统一日志工具。
 * 
 * 与 CryptoLogger 的关系：
 * - LoggingInterceptor: 拦截器链钩子，记录加密/解密的进入和退出
 * - CryptoLogger: 通用日志工具，可在任何地方调用
 * 
 * 两者结合使用可以获得完整的操作日志。
 */
class LoggingInterceptor(
    private val tag: String = "Interceptor",
    override val priority: Int = 100
) : CryptoInterceptor {

    override val name: String = "LoggingInterceptor"

    override fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        CryptoLogger.v(tag, "[$algorithm] → beforeEncrypt: ${plaintext.size} bytes")
        return plaintext
    }

    override fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        CryptoLogger.v(tag, "[$algorithm] ← afterEncrypt: ${ciphertext.size} bytes")
        return ciphertext
    }

    override fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        CryptoLogger.v(tag, "[$algorithm] → beforeDecrypt: ${ciphertext.size} bytes")
        return ciphertext
    }

    override fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        CryptoLogger.v(tag, "[$algorithm] ← afterDecrypt: ${plaintext.size} bytes")
        return plaintext
    }
}
