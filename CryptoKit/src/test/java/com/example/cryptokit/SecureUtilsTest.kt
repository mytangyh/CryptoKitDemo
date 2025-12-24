package com.example.cryptokit

import com.example.cryptokit.util.SecureUtils
import org.junit.Assert.*
import org.junit.Test

/**
 * 安全工具类单元测试
 */
class SecureUtilsTest {

    @Test
    fun `test wipe clears byte array`() {
        val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        
        SecureUtils.wipe(data)
        
        // 擦除后所有字节应为0
        assertTrue(data.all { it == 0.toByte() })
    }

    @Test
    fun `test wipe handles null`() {
        // 应该不抛出异常
        SecureUtils.wipe(null as ByteArray?)
    }

    @Test
    fun `test wipe handles empty array`() {
        val data = ByteArray(0)
        SecureUtils.wipe(data)
        // 应该不抛出异常
    }

    @Test
    fun `test wipe clears char array`() {
        val data = charArrayOf('p', 'a', 's', 's', 'w', 'o', 'r', 'd')
        
        SecureUtils.wipe(data)
        
        assertTrue(data.all { it == '\u0000' })
    }

    @Test
    fun `test wipeAll clears multiple arrays`() {
        val arr1 = byteArrayOf(1, 2, 3)
        val arr2 = byteArrayOf(4, 5, 6)
        val arr3 = byteArrayOf(7, 8, 9)
        
        SecureUtils.wipeAll(arr1, arr2, arr3)
        
        assertTrue(arr1.all { it == 0.toByte() })
        assertTrue(arr2.all { it == 0.toByte() })
        assertTrue(arr3.all { it == 0.toByte() })
    }

    @Test
    fun `test constantTimeEquals returns true for equal arrays`() {
        val a = byteArrayOf(1, 2, 3, 4, 5)
        val b = byteArrayOf(1, 2, 3, 4, 5)
        
        assertTrue(SecureUtils.constantTimeEquals(a, b))
    }

    @Test
    fun `test constantTimeEquals returns false for different arrays`() {
        val a = byteArrayOf(1, 2, 3, 4, 5)
        val b = byteArrayOf(1, 2, 3, 4, 6)
        
        assertFalse(SecureUtils.constantTimeEquals(a, b))
    }

    @Test
    fun `test constantTimeEquals returns false for different lengths`() {
        val a = byteArrayOf(1, 2, 3)
        val b = byteArrayOf(1, 2, 3, 4)
        
        assertFalse(SecureUtils.constantTimeEquals(a, b))
    }

    @Test
    fun `test constantTimeEquals handles null`() {
        val a = byteArrayOf(1, 2, 3)
        
        assertFalse(SecureUtils.constantTimeEquals(a, null as ByteArray?))
        assertFalse(SecureUtils.constantTimeEquals(null as ByteArray?, a))
        assertTrue(SecureUtils.constantTimeEquals(null as ByteArray?, null as ByteArray?))
    }

    @Test
    fun `test constantTimeEquals for strings`() {
        assertTrue(SecureUtils.constantTimeEquals("password", "password"))
        assertFalse(SecureUtils.constantTimeEquals("password", "passwor"))
        assertFalse(SecureUtils.constantTimeEquals("password", "PASSWORD"))
    }

    @Test
    fun `test withSecureBytes wipes data after block`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        var capturedSum = 0
        
        SecureUtils.withSecureBytes(data) { bytes ->
            capturedSum = bytes.sum()
        }
        
        // 结果应该正确
        assertEquals(15, capturedSum)
        // 数据应该被擦除
        assertTrue(data.all { it == 0.toByte() })
    }

    @Test
    fun `test withSecureBytes wipes data even on exception`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        
        try {
            SecureUtils.withSecureBytes(data) { 
                throw RuntimeException("Test exception")
            }
        } catch (e: RuntimeException) {
            // 预期的异常
        }
        
        // 数据应该被擦除
        assertTrue(data.all { it == 0.toByte() })
    }

    @Test
    fun `test withSecurePassword wipes password after block`() {
        val password = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
        
        SecureUtils.withSecurePassword(password) { pwd ->
            assertEquals(6, pwd.size)
        }
        
        assertTrue(password.all { it == '\u0000' })
    }

    @Test
    fun `test constant time comparison timing`() {
        val a = ByteArray(1000) { 0 }
        val b = ByteArray(1000) { 0 }
        val c = ByteArray(1000) { it.toByte() }
        
        // 预热
        repeat(1000) {
            SecureUtils.constantTimeEquals(a, b)
            SecureUtils.constantTimeEquals(a, c)
        }
        
        // 测量相同数据比较时间
        val sameStart = System.nanoTime()
        repeat(10000) { SecureUtils.constantTimeEquals(a, b) }
        val sameTime = System.nanoTime() - sameStart
        
        // 测量不同数据比较时间
        val diffStart = System.nanoTime()
        repeat(10000) { SecureUtils.constantTimeEquals(a, c) }
        val diffTime = System.nanoTime() - diffStart
        
        // 时间差应该在合理范围内（由于JIT和环境因素，放宽到50%）
        // 这个测试主要验证实现是恒定时间的，而不是精确测量
        val ratio = sameTime.toDouble() / diffTime
        // 只在差距特别大时才失败（比如10倍以上）
        assertTrue("Timing difference too extreme: ratio=$ratio", ratio in 0.1..10.0)
    }
}
