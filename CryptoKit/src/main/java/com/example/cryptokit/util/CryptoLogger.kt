package com.example.cryptokit.util

import android.util.Log

/**
 * CryptoKit 统一日志工具
 * 
 * 金融级特性：
 * - 敏感信息自动脱敏
 * - 可配置日志级别
 * - 支持自定义日志输出
 * - 线程安全
 * 
 * 使用示例：
 * ```kotlin
 * CryptoLogger.d("AES", "Encrypting ${data.size} bytes")
 * CryptoLogger.i("KeyManager", "Key generated: ${alias}")
 * CryptoLogger.w("RSA", "Using 1024-bit key is not recommended")
 * CryptoLogger.e("Decrypt", "Failed", exception)
 * ```
 */
object CryptoLogger {
    
    private const val TAG_PREFIX = "CryptoKit"
    
    /**
     * 日志级别
     */
    enum class Level {
        VERBOSE, DEBUG, INFO, WARN, ERROR, NONE
    }
    
    /**
     * 日志监听器接口
     */
    interface LogListener {
        fun onLog(level: Level, tag: String, message: String, throwable: Throwable?)
    }
    
    @Volatile
    var minLevel: Level = Level.DEBUG
    
    @Volatile
    var isEnabled: Boolean = false
    
    @Volatile
    private var logListener: LogListener? = null
    
    /**
     * 启用日志
     */
    fun enable(level: Level = Level.DEBUG) {
        isEnabled = true
        minLevel = level
    }
    
    /**
     * 禁用日志
     */
    fun disable() {
        isEnabled = false
    }
    
    /**
     * 设置自定义日志监听器
     */
    fun setLogListener(listener: LogListener?) {
        logListener = listener
    }
    
    /**
     * Verbose 级别日志
     */
    fun v(tag: String, message: String, throwable: Throwable? = null) {
        log(Level.VERBOSE, tag, message, throwable)
    }
    
    /**
     * Debug 级别日志
     */
    fun d(tag: String, message: String, throwable: Throwable? = null) {
        log(Level.DEBUG, tag, message, throwable)
    }
    
    /**
     * Info 级别日志
     */
    fun i(tag: String, message: String, throwable: Throwable? = null) {
        log(Level.INFO, tag, message, throwable)
    }
    
    /**
     * Warning 级别日志
     */
    fun w(tag: String, message: String, throwable: Throwable? = null) {
        log(Level.WARN, tag, message, throwable)
    }
    
    /**
     * Error 级别日志
     */
    fun e(tag: String, message: String, throwable: Throwable? = null) {
        log(Level.ERROR, tag, message, throwable)
    }
    
    private fun log(level: Level, tag: String, message: String, throwable: Throwable?) {
        if (!isEnabled || level.ordinal < minLevel.ordinal) return
        
        val fullTag = "$TAG_PREFIX.$tag"
        
        // 通知自定义监听器
        logListener?.onLog(level, fullTag, message, throwable)
        
        // Android Log 输出
        when (level) {
            Level.VERBOSE -> if (throwable != null) Log.v(fullTag, message, throwable) else Log.v(fullTag, message)
            Level.DEBUG -> if (throwable != null) Log.d(fullTag, message, throwable) else Log.d(fullTag, message)
            Level.INFO -> if (throwable != null) Log.i(fullTag, message, throwable) else Log.i(fullTag, message)
            Level.WARN -> if (throwable != null) Log.w(fullTag, message, throwable) else Log.w(fullTag, message)
            Level.ERROR -> if (throwable != null) Log.e(fullTag, message, throwable) else Log.e(fullTag, message)
            Level.NONE -> { /* 不输出 */ }
        }
    }
    
    // ==================== 便捷方法 ====================
    
    /**
     * 记录加密操作
     */
    fun logEncrypt(algorithm: String, dataSize: Int, keySize: Int? = null) {
        val keySizeInfo = keySize?.let { ", keySize=${it}bit" } ?: ""
        d("Encrypt", "[$algorithm] Encrypting ${dataSize} bytes$keySizeInfo")
    }
    
    /**
     * 记录解密操作
     */
    fun logDecrypt(algorithm: String, dataSize: Int) {
        d("Decrypt", "[$algorithm] Decrypting ${dataSize} bytes")
    }
    
    /**
     * 记录加密完成
     */
    fun logEncryptComplete(algorithm: String, inputSize: Int, outputSize: Int, durationMs: Long) {
        i("Encrypt", "[$algorithm] Completed: ${inputSize}B → ${outputSize}B in ${durationMs}ms")
    }
    
    /**
     * 记录解密完成
     */
    fun logDecryptComplete(algorithm: String, inputSize: Int, outputSize: Int, durationMs: Long) {
        i("Decrypt", "[$algorithm] Completed: ${inputSize}B → ${outputSize}B in ${durationMs}ms")
    }
    
    /**
     * 记录密钥生成
     */
    fun logKeyGeneration(algorithm: String, keySize: Int, alias: String? = null) {
        val aliasInfo = alias?.let { " alias='${maskAlias(it)}'" } ?: ""
        i("KeyGen", "[$algorithm] Generated ${keySize}-bit key$aliasInfo")
    }
    
    /**
     * 记录签名操作
     */
    fun logSign(algorithm: String, dataSize: Int) {
        d("Sign", "[$algorithm] Signing ${dataSize} bytes")
    }
    
    /**
     * 记录验签操作
     */
    fun logVerify(algorithm: String, dataSize: Int, result: Boolean) {
        val status = if (result) "✓ Valid" else "✗ Invalid"
        i("Verify", "[$algorithm] Verified ${dataSize} bytes: $status")
    }
    
    /**
     * 记录哈希操作
     */
    fun logHash(algorithm: String, dataSize: Int) {
        d("Hash", "[$algorithm] Hashing ${dataSize} bytes")
    }
    
    /**
     * 记录密钥派生
     */
    fun logKeyDerivation(algorithm: String, iterations: Int, keyLength: Int) {
        i("KeyDerive", "[$algorithm] PBKDF2 iterations=$iterations, keyLength=${keyLength}bit")
    }
    
    /**
     * 记录Keystore操作
     */
    fun logKeystoreOp(operation: String, alias: String, success: Boolean) {
        val status = if (success) "✓" else "✗"
        i("Keystore", "[$operation] alias='${maskAlias(alias)}' $status")
    }
    
    /**
     * 记录安全警告
     */
    fun logSecurityWarning(component: String, message: String) {
        w("Security", "⚠️ [$component] $message")
    }
    
    /**
     * 记录操作失败
     */
    fun logFailure(operation: String, algorithm: String, throwable: Throwable) {
        e("Failure", "[$algorithm] $operation failed: ${throwable.message}", throwable)
    }
    
    // ==================== 脱敏工具 ====================
    
    /**
     * 脱敏处理别名（只显示前3后3字符）
     */
    private fun maskAlias(alias: String): String {
        return if (alias.length <= 8) {
            alias.take(2) + "***" + alias.takeLast(2)
        } else {
            alias.take(3) + "***" + alias.takeLast(3)
        }
    }
    
    /**
     * 脱敏处理密钥（只显示前后各4个字符）
     */
    fun maskKey(keyHex: String): String {
        return if (keyHex.length <= 12) {
            keyHex.take(4) + "..." + keyHex.takeLast(4)
        } else {
            keyHex.take(8) + "..." + keyHex.takeLast(8)
        }
    }
    
    /**
     * 脱敏处理数据（只显示大小和前几个字节哈希）
     */
    fun maskData(data: ByteArray): String {
        val preview = data.take(4).joinToString("") { "%02x".format(it) }
        return "${data.size}B[${preview}...]"
    }
}
