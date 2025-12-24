package com.example.cryptokit.exception

/**
 * 密钥未找到异常
 */
class KeyNotFoundException(
    alias: String,
    cause: Throwable? = null
) : CryptoException("Key not found: $alias", cause)
