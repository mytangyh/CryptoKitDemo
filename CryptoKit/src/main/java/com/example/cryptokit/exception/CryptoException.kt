package com.example.cryptokit.exception

/**
 * CryptoKit基础异常类
 */
open class CryptoException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)
