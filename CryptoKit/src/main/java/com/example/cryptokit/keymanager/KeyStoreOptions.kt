package com.example.cryptokit.keymanager

/**
 * 密钥存储选项
 */
data class KeyStoreOptions(
    val requireUserAuthentication: Boolean = false,
    val authenticationTimeout: Int = 0,
    val requireBiometric: Boolean = false,
    val invalidatedByBiometricEnrollment: Boolean = true,
    val isStrongBoxBacked: Boolean = false
)
