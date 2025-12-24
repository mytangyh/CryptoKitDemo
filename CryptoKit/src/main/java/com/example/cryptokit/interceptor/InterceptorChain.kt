package com.example.cryptokit.interceptor

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 拦截器链管理器
 * 管理所有注册的拦截器，并按优先级排序执行
 * 
 * 线程安全：使用CopyOnWriteArrayList和AtomicBoolean确保并发安全
 */
object InterceptorChain {
    
    // 使用线程安全的集合
    private val interceptors = CopyOnWriteArrayList<CryptoInterceptor>()
    
    // 使用原子布尔确保可见性
    @Volatile 
    private var enabled = AtomicBoolean(false)

    /**
     * 启用拦截器
     */
    fun enable() {
        enabled.set(true)
    }

    /**
     * 禁用拦截器
     */
    fun disable() {
        enabled.set(false)
    }

    /**
     * 是否启用
     */
    fun isEnabled(): Boolean = enabled.get()

    /**
     * 添加拦截器（线程安全）
     */
    @Synchronized
    fun addInterceptor(interceptor: CryptoInterceptor) {
        // 防止重复添加
        if (interceptors.none { it.name == interceptor.name }) {
            interceptors.add(interceptor)
            // 创建新的排序列表
            val sorted = interceptors.sortedBy { it.priority }
            interceptors.clear()
            interceptors.addAll(sorted)
        }
    }

    /**
     * 移除拦截器（线程安全）
     */
    fun removeInterceptor(interceptor: CryptoInterceptor) {
        interceptors.removeIf { it.name == interceptor.name }
    }

    /**
     * 移除所有拦截器
     */
    fun clearInterceptors() {
        interceptors.clear()
    }

    /**
     * 获取所有拦截器（返回不可变副本）
     */
    fun getInterceptors(): List<CryptoInterceptor> = interceptors.toList()

    /**
     * 执行加密前拦截
     */
    fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray {
        if (!enabled.get()) return plaintext
        var data = plaintext
        // CopyOnWriteArrayList迭代时线程安全
        for (interceptor in interceptors) {
            data = interceptor.beforeEncrypt(data, algorithm)
        }
        return data
    }

    /**
     * 执行加密后拦截
     */
    fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray {
        if (!enabled.get()) return ciphertext
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
        if (!enabled.get()) return ciphertext
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
        if (!enabled.get()) return plaintext
        var data = plaintext
        for (interceptor in interceptors) {
            data = interceptor.afterDecrypt(data, algorithm)
        }
        return data
    }

    /**
     * 快捷方法：添加日志拦截器
     */
    @Synchronized
    fun enableLogging(tag: String = "CryptoKit") {
        enable()
        addInterceptor(LoggingInterceptor(tag))
    }

    /**
     * 快捷方法：添加性能监控拦截器
     */
    @Synchronized
    fun enablePerformanceMonitoring(warningThresholdMs: Long = 100) {
        enable()
        addInterceptor(PerformanceInterceptor(warningThresholdMs = warningThresholdMs))
    }

    /**
     * 快捷方法：启用调试模式（日志+性能）
     */
    @Synchronized
    fun enableDebugMode() {
        enable()
        addInterceptor(PerformanceInterceptor())
        addInterceptor(LoggingInterceptor())
    }
    
    /**
     * 重置为初始状态
     */
    @Synchronized
    fun reset() {
        disable()
        clearInterceptors()
    }
}
