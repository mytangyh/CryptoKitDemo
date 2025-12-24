package com.example.cryptokit.keymanager

/**
 * 密钥存储选项
 * 
 * 金融级安全配置：
 * - requireUserAuthentication: 操作前需用户认证
 * - isStrongBoxBacked: 使用硬件安全模块
 * - requireUnlockedDevice: 仅在设备解锁时可用
 */
data class KeyStoreOptions(
    val requireUserAuthentication: Boolean = false,
    val authenticationTimeout: Int = 0,
    val requireBiometric: Boolean = false,
    val invalidatedByBiometricEnrollment: Boolean = true,
    val isStrongBoxBacked: Boolean = false,
    val requireUnlockedDevice: Boolean = false
) {
    companion object {
        /**
         * 金融级安全配置
         */
        fun financialGrade(): KeyStoreOptions = KeyStoreOptions(
            requireUserAuthentication = true,
            authenticationTimeout = 30,
            requireBiometric = true,
            invalidatedByBiometricEnrollment = true,
            isStrongBoxBacked = true,
            requireUnlockedDevice = true
        )
        
        /**
         * 标准安全配置
         */
        fun standard(): KeyStoreOptions = KeyStoreOptions()
    }
}
