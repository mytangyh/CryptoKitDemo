package com.example.cryptokit.interceptor

import com.example.cryptokit.util.CryptoLogger

/**
 * 性能监控拦截器
 * 
 * 记录加密/解密操作的耗时，超过阈值会输出警告。
 * 内部复用 [CryptoLogger] 统一日志工具。
 */
class PerformanceInterceptor(
    private val tag: String = "Perf",
    override val priority: Int = 50,
    private val warningThresholdMs: Long = 100
) : CryptoInterceptor {

    override val name: String = "PerformanceInterceptor"

    private val startTimes = ThreadLocal<Long>()

    override fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        startTimes.set(System.nanoTime())
        return plaintext
    }

    override fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        logDuration("Encrypt", algorithm, plaintext = null, result = ciphertext)
        return ciphertext
    }

    override fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        startTimes.set(System.nanoTime())
        return ciphertext
    }

    override fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        logDuration("Decrypt", algorithm, plaintext = plaintext, result = null)
        return plaintext
    }

    private fun logDuration(operation: String, algorithm: String, plaintext: ByteArray?, result: ByteArray?) {
        val startTime = startTimes.get() ?: return
        try {
            val durationNs = System.nanoTime() - startTime
            val durationMs = durationNs / 1_000_000.0

            val size = result?.size ?: plaintext?.size ?: 0
            val message = "[$algorithm] $operation completed in %.2f ms (%d bytes)".format(durationMs, size)

            if (durationMs >= warningThresholdMs) {
                CryptoLogger.w(tag, "⚠️ SLOW: $message")
            } else {
                CryptoLogger.d(tag, "✓ $message")
            }
        } finally {
            startTimes.remove()
        }
    }
}
