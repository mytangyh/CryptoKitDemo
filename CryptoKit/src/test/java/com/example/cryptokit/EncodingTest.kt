package com.example.cryptokit

import com.example.cryptokit.core.encoding.HexEncoder
import org.junit.Assert.*
import org.junit.Test

/**
 * 编码工具单元测试
 * 
 * 注意：Base64Encoder使用android.util.Base64，只能在Android测试中运行
 * 此处仅测试HexEncoder
 */
class EncodingTest {

    private val testData = "Hello, CryptoKit! 你好！".toByteArray()

    // ==================== Hex 测试 ====================

    @Test
    fun `test Hex encode and decode`() {
        val encoder = HexEncoder.getInstance()
        
        val encoded = encoder.encode(testData)
        val decoded = encoder.decode(encoded)
        
        assertArrayEquals(testData, decoded)
    }

    @Test
    fun `test Hex encode produces lowercase`() {
        val encoder = HexEncoder.getInstance()
        val data = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        
        val encoded = encoder.encode(data)
        
        assertEquals("abcdef", encoded)
    }

    @Test
    fun `test Hex decode handles uppercase`() {
        val encoder = HexEncoder.getInstance()
        
        val decoded = encoder.decode("ABCDEF")
        
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()), decoded)
    }

    @Test
    fun `test Hex decode handles mixed case`() {
        val encoder = HexEncoder.getInstance()
        
        val decoded = encoder.decode("AbCdEf")
        
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()), decoded)
    }

    @Test
    fun `test Hex empty data`() {
        val encoder = HexEncoder.getInstance()
        
        val encoded = encoder.encode(ByteArray(0))
        val decoded = encoder.decode("")
        
        assertEquals("", encoded)
        assertEquals(0, decoded.size)
    }

    @Test
    fun `test Hex known vectors`() {
        val encoder = HexEncoder.getInstance()
        
        assertEquals("00", encoder.encode(byteArrayOf(0)))
        assertEquals("ff", encoder.encode(byteArrayOf(-1)))
        assertEquals("0102030405", encoder.encode(byteArrayOf(1, 2, 3, 4, 5)))
    }

    @Test
    fun `test Hex length is double of bytes`() {
        val encoder = HexEncoder.getInstance()
        val data = ByteArray(100) { it.toByte() }
        
        val encoded = encoder.encode(data)
        
        assertEquals(200, encoded.length)
    }

    @Test
    fun `test Hex roundtrip with special bytes`() {
        val encoder = HexEncoder.getInstance()
        val data = byteArrayOf(0, 127, -128, -1, 1, -2)
        
        val encoded = encoder.encode(data)
        val decoded = encoder.decode(encoded)
        
        assertArrayEquals(data, decoded)
    }
}

