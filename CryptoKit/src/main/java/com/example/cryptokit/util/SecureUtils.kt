package com.example.cryptokit.util

import java.security.SecureRandom
import java.util.Arrays

/**
 * 安全工具类
 * 用于敏感数据的安全擦除和处理
 * 
 * 金融级安全要求：
 * - 敏感数据使用后立即清零
 * - 防止内存残留被提取
 */
object SecureUtils {
    
    private val secureRandom = SecureRandom()
    
    /**
     * 安全擦除字节数组
     * 先用随机数覆盖，再用零覆盖，防止内存残留分析
     */
    fun wipe(data: ByteArray?) {
        if (data == null || data.isEmpty()) return
        
        // 第一次：随机数覆盖
        secureRandom.nextBytes(data)
        // 第二次：零覆盖
        Arrays.fill(data, 0.toByte())
    }
    
    /**
     * 安全擦除字符数组（用于密码）
     */
    fun wipe(data: CharArray?) {
        if (data == null || data.isEmpty()) return
        Arrays.fill(data, '\u0000')
    }
    
    /**
     * 安全擦除多个字节数组
     */
    fun wipeAll(vararg arrays: ByteArray?) {
        arrays.forEach { wipe(it) }
    }
    
    /**
     * 安全比较两个字节数组（恒定时间比较，防止时序攻击）
     */
    fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean {
        if (a == null || b == null) return a === b
        if (a.size != b.size) return false
        
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }
    
    /**
     * 安全比较两个字符串（恒定时间比较，防止时序攻击）
     */
    fun constantTimeEquals(a: String?, b: String?): Boolean {
        if (a == null || b == null) return a === b
        return constantTimeEquals(a.toByteArray(), b.toByteArray())
    }
    
    /**
     * 创建一个可自动擦除的作用域
     */
    inline fun <T> withSecureBytes(data: ByteArray, block: (ByteArray) -> T): T {
        return try {
            block(data)
        } finally {
            wipe(data)
        }
    }
    
    /**
     * 创建一个可自动擦除的密码作用域
     */
    inline fun <T> withSecurePassword(password: CharArray, block: (CharArray) -> T): T {
        return try {
            block(password)
        } finally {
            wipe(password)
        }
    }
}
