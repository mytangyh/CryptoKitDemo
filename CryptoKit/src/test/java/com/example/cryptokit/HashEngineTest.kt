package com.example.cryptokit

import com.example.cryptokit.core.hash.StandardHashEngine
import org.junit.Assert.*
import org.junit.Test

/**
 * 哈希引擎单元测试
 */
class HashEngineTest {

    private val testData = "Hello, CryptoKit!".toByteArray()
    private val testString = "Hello, CryptoKit!"

    @Test
    fun `test SHA-256 hash`() {
        val engine = StandardHashEngine.sha256()
        val hash = engine.hash(testData)

        assertEquals(32, hash.size) // SHA-256 = 256 bits = 32 bytes
        
        // 验证哈希值是确定性的
        val hash2 = engine.hash(testData)
        assertArrayEquals(hash, hash2)
    }

    @Test
    fun `test SHA-512 hash`() {
        val engine = StandardHashEngine.sha512()
        val hash = engine.hash(testData)

        assertEquals(64, hash.size) // SHA-512 = 512 bits = 64 bytes
    }

    @Test
    fun `test SHA-1 hash`() {
        val engine = StandardHashEngine.sha1()
        val hash = engine.hash(testData)

        assertEquals(20, hash.size) // SHA-1 = 160 bits = 20 bytes
    }

    @Test
    fun `test MD5 hash`() {
        val engine = StandardHashEngine.md5()
        val hash = engine.hash(testData)

        assertEquals(16, hash.size) // MD5 = 128 bits = 16 bytes
    }

    @Test
    fun `test different inputs produce different hashes`() {
        val engine = StandardHashEngine.sha256()
        
        val hash1 = engine.hash("data1".toByteArray())
        val hash2 = engine.hash("data2".toByteArray())

        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun `test empty data hash`() {
        val engine = StandardHashEngine.sha256()
        val hash = engine.hash(ByteArray(0))

        assertEquals(32, hash.size)
        // SHA-256 of empty string is well-known
        val expectedHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assertEquals(expectedHex, hash.toHex())
    }

    @Test
    fun `test HMAC-SHA256`() {
        val engine = StandardHashEngine.sha256()
        val key = "secret-key".toByteArray()
        
        val hmac = engine.hmac(testData, key)

        assertEquals(32, hmac.size)
        
        // HMAC is deterministic with same key
        val hmac2 = engine.hmac(testData, key)
        assertArrayEquals(hmac, hmac2)
    }

    @Test
    fun `test HMAC with different keys produces different results`() {
        val engine = StandardHashEngine.sha256()
        val key1 = "key1".toByteArray()
        val key2 = "key2".toByteArray()
        
        val hmac1 = engine.hmac(testData, key1)
        val hmac2 = engine.hmac(testData, key2)

        assertFalse(hmac1.contentEquals(hmac2))
    }

    @Test
    fun `test known SHA-256 vector`() {
        val engine = StandardHashEngine.sha256()
        val hash = engine.hash("abc".toByteArray())
        
        // Known SHA-256("abc") value
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        assertEquals(expected, hash.toHex())
    }

    @Test
    fun `test digest length property`() {
        assertEquals(32, StandardHashEngine.sha256().digestLength)
        assertEquals(64, StandardHashEngine.sha512().digestLength)
        assertEquals(20, StandardHashEngine.sha1().digestLength)
        assertEquals(16, StandardHashEngine.md5().digestLength)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
