package com.example.cryptokit.exception

/**
 * 无效算法异常
 */
class InvalidAlgorithmException(
    algorithm: String,
    cause: Throwable? = null
) : CryptoException("Invalid or unsupported algorithm: $algorithm", cause)
