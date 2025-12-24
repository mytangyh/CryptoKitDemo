package com.example.cryptokit.interceptor

/**
 * 拦截器链管理器
 * 管理所有注册的拦截器，并按优先级排序执行
 */
object InterceptorChain {
    
    private val interceptors = mutableListOf<CryptoInterceptor>()
    private var enabled = false

    /**
     * 启用拦截器
     */
    fun enable() {
        enabled = true
    }

    /**
     * 禁用拦截器
     */
    fun disable() {
        enabled = false
    }

    /**
     * 是否启用
     */
    fun isEnabled(): Boolean = enabled

    /**
     * 添加拦截器
     */
    fun addInterceptor(interceptor: CryptoInterceptor) {
        interceptors.add(interceptor)
        interceptors.sortBy { it.priority }
    }

    /**
     * 移除拦截器
     */
    fun removeInterceptor(interceptor: CryptoInterceptor) {
        interceptors.remove(interceptor)
    }

    /**
     * 移除所有拦截器
     */
    fun clearInterceptors() {
        interceptors.clear()
    }

    /**
     * 获取所有拦截器
     */
    fun getInterceptors(): List<CryptoInterceptor> = interceptors.toList()

    /**
     * 执行加密前拦截
     */
    fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        if (!enabled) return plaintext
        var data = plaintext
        for (interceptor in interceptors) {
            data = interceptor.beforeEncrypt(data, algorithm)
        }
        return data
    }

    /**
     * 执行加密后拦截
     */
    fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        if (!enabled) return ciphertext
        var data = ciphertext
        for (interceptor in interceptors) {
            data = interceptor.afterEncrypt(data, algorithm)
        }
        return data
    }

    /**
     * 执行解密前拦截
     */
    fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        if (!enabled) return ciphertext
        var data = ciphertext
        for (interceptor in interceptors) {
            data = interceptor.beforeDecrypt(data, algorithm)
        }
        return data
    }

    /**
     * 执行解密后拦截
     */
    fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        if (!enabled) return plaintext
        var data = plaintext
        for (interceptor in interceptors) {
            data = interceptor.afterDecrypt(data, algorithm)
        }
        return data
    }

    /**
     * 快捷方法：添加日志拦截器
     */
    fun enableLogging(tag: String = "CryptoKit") {
        enable()
        addInterceptor(LoggingInterceptor(tag))
    }

    /**
     * 快捷方法：添加性能监控拦截器
     */
    fun enablePerformanceMonitoring(warningThresholdMs: Long = 100) {
        enable()
        addInterceptor(PerformanceInterceptor(warningThresholdMs = warningThresholdMs))
    }

    /**
     * 快捷方法：启用调试模式（日志+性能）
     */
    fun enableDebugMode() {
        enable()
        addInterceptor(PerformanceInterceptor())
        addInterceptor(LoggingInterceptor())
    }
}
