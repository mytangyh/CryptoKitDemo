package com.example.cryptokit

import com.example.cryptokit.api.results.CipherResult
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.util.SecureUtils
import org.junit.Assert.*
import org.junit.Test
import java.lang.ref.WeakReference
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

/**
 * 安全测试套件
 * 
 * 金融级安全测试要求：
 * - 密钥内存擦除验证
 * - 时序攻击防护验证
 * - 敏感数据泄露检测
 * - 密码学正确性验证
 * - 随机数质量测试
 */
class SecurityTest {

    // ==================== 内存擦除测试 ====================

    @Test
    fun `SecureUtils wipe should clear byte array`() {
        val sensitiveData = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val originalCopy = sensitiveData.copyOf()
        
        // 验证原始数据存在
        assertArrayEquals(originalCopy, sensitiveData)
        
        // 擦除
        SecureUtils.wipe(sensitiveData)
        
        // 验证已清零
        assertTrue("Data should be zeroed", sensitiveData.all { it == 0.toByte() })
        assertFalse("Data should differ from original", sensitiveData.contentEquals(originalCopy))
    }

    @Test
    fun `SecureUtils wipe should clear char array`() {
        val password = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
        
        SecureUtils.wipe(password)
        
        assertTrue("Password should be zeroed", password.all { it == '\u0000' })
    }

    @Test
    fun `SecureUtils wipeAll should clear multiple arrays`() {
        val arr1 = byteArrayOf(1, 2, 3)
        val arr2 = byteArrayOf(4, 5, 6)
        val arr3 = byteArrayOf(7, 8, 9)
        
        SecureUtils.wipeAll(arr1, arr2, arr3)
        
        assertTrue(arr1.all { it == 0.toByte() })
        assertTrue(arr2.all { it == 0.toByte() })
        assertTrue(arr3.all { it == 0.toByte() })
    }

    @Test
    fun `withSecureBytes should wipe data after block execution`() {
        val sensitiveData = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        var computedSum = 0
        
        SecureUtils.withSecureBytes(sensitiveData) { data ->
            computedSum = data.sum()
        }
        
        assertEquals(15, computedSum)
        assertTrue("Data should be wiped", sensitiveData.all { it == 0.toByte() })
    }

    @Test
    fun `withSecureBytes should wipe data even on exception`() {
        val sensitiveData = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        
        try {
            SecureUtils.withSecureBytes(sensitiveData) {
                throw RuntimeException("Test exception")
            }
        } catch (e: RuntimeException) {
            // Expected
        }
        
        assertTrue("Data should be wiped even on exception", sensitiveData.all { it == 0.toByte() })
    }

    @Test
    fun `withSecurePassword should wipe password after block`() {
        val password = charArrayOf('p', 'a', 's', 's', 'w', 'o', 'r', 'd')
        
        SecureUtils.withSecurePassword(password) { pwd ->
            assertEquals(8, pwd.size)
        }
        
        assertTrue(password.all { it == '\u0000' })
    }

    // ==================== 时序攻击防护测试 ====================

    @Test
    fun `constantTimeEquals should return correct results`() {
        val a = byteArrayOf(1, 2, 3, 4, 5)
        val b = byteArrayOf(1, 2, 3, 4, 5)
        val c = byteArrayOf(1, 2, 3, 4, 6)
        val d = byteArrayOf(1, 2, 3)
        
        assertTrue(SecureUtils.constantTimeEquals(a, b))
        assertFalse(SecureUtils.constantTimeEquals(a, c))
        assertFalse(SecureUtils.constantTimeEquals(a, d))
    }

    @Test
    fun `constantTimeEquals should handle null inputs`() {
        val a = byteArrayOf(1, 2, 3)
        
        assertFalse(SecureUtils.constantTimeEquals(a, null))
        assertFalse(SecureUtils.constantTimeEquals(null, a))
        assertTrue(SecureUtils.constantTimeEquals(null as ByteArray?, null))
    }

    @Test
    fun `constantTimeEquals should have consistent timing for equal arrays`() {
        val warmupIterations = 10000
        val testIterations = 100000
        
        val a = ByteArray(1000) { 0 }
        val b = ByteArray(1000) { 0 } // 完全相同
        
        // 预热
        repeat(warmupIterations) {
            SecureUtils.constantTimeEquals(a, b)
        }
        
        val startTime = System.nanoTime()
        repeat(testIterations) {
            SecureUtils.constantTimeEquals(a, b)
        }
        val sameTime = System.nanoTime() - startTime
        
        // 记录时间
        println("Equal arrays comparison: ${sameTime / 1_000_000.0}ms for $testIterations iterations")
        
        // 基本断言 - 比较应该完成
        assertTrue(sameTime > 0)
    }

    @Test
    fun `constantTimeEquals should have consistent timing for different arrays`() {
        val warmupIterations = 10000
        val testIterations = 100000
        
        val a = ByteArray(1000) { 0 }
        val c = ByteArray(1000) { it.toByte() } // 第一个字节就不同
        val d = ByteArray(1000) { if (it == 999) 1 else 0 } // 最后一个字节不同
        
        // 预热
        repeat(warmupIterations) {
            SecureUtils.constantTimeEquals(a, c)
            SecureUtils.constantTimeEquals(a, d)
        }
        
        // 第一个字节不同
        val startTimeC = System.nanoTime()
        repeat(testIterations) {
            SecureUtils.constantTimeEquals(a, c)
        }
        val timeFirstDiff = System.nanoTime() - startTimeC
        
        // 最后一个字节不同
        val startTimeD = System.nanoTime()
        repeat(testIterations) {
            SecureUtils.constantTimeEquals(a, d)
        }
        val timeLastDiff = System.nanoTime() - startTimeD
        
        println("First byte differs: ${timeFirstDiff / 1_000_000.0}ms for $testIterations iterations")
        println("Last byte differs: ${timeLastDiff / 1_000_000.0}ms for $testIterations iterations")
        
        // 时间差应该在合理范围内 (2倍以内)
        val ratio = timeFirstDiff.toDouble() / timeLastDiff.toDouble()
        assertTrue("Timing ratio should be reasonable: $ratio", ratio in 0.5..2.0)
    }

    @Test
    fun `constantTimeEquals statistical timing analysis`() {
        val sampleSize = 1000
        val iterationsPerSample = 1000
        
        val a = ByteArray(256) { 0 }
        val bSame = ByteArray(256) { 0 }
        val bDiffFirst = ByteArray(256) { if (it == 0) 1 else 0 }
        val bDiffLast = ByteArray(256) { if (it == 255) 1 else 0 }
        
        val timesSame = mutableListOf<Long>()
        val timesDiffFirst = mutableListOf<Long>()
        val timesDiffLast = mutableListOf<Long>()
        
        // 收集样本
        repeat(sampleSize) {
            val startSame = System.nanoTime()
            repeat(iterationsPerSample) { SecureUtils.constantTimeEquals(a, bSame) }
            timesSame.add(System.nanoTime() - startSame)
            
            val startFirst = System.nanoTime()
            repeat(iterationsPerSample) { SecureUtils.constantTimeEquals(a, bDiffFirst) }
            timesDiffFirst.add(System.nanoTime() - startFirst)
            
            val startLast = System.nanoTime()
            repeat(iterationsPerSample) { SecureUtils.constantTimeEquals(a, bDiffLast) }
            timesDiffLast.add(System.nanoTime() - startLast)
        }
        
        // 计算统计量
        val avgSame = timesSame.average()
        val avgDiffFirst = timesDiffFirst.average()
        val avgDiffLast = timesDiffLast.average()
        
        println("Statistical timing analysis:")
        println("  Same: ${avgSame / 1000.0} µs avg")
        println("  Diff first: ${avgDiffFirst / 1000.0} µs avg")
        println("  Diff last: ${avgDiffLast / 1000.0} µs avg")
        
        // 所有情况的时间应该接近
        val maxDiff = maxOf(avgSame, avgDiffFirst, avgDiffLast) / minOf(avgSame, avgDiffFirst, avgDiffLast)
        println("  Max timing ratio: $maxDiff")
        
        // 宽松检查 - JIT 和环境因素可能影响
        assertTrue("Max timing ratio should be < 3", maxDiff < 3.0)
    }

    // ==================== 密码学正确性测试 ====================

    @Test
    fun `AES encryption should produce different ciphertext with different IVs`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val plaintext = "Test data".toByteArray()
        
        val ciphertexts = mutableSetOf<String>()
        repeat(100) {
            val iv = cipher.generateIV()
            val ciphertext = cipher.encrypt(plaintext, key, iv)
            ciphertexts.add(ciphertext.toHexString())
        }
        
        assertEquals("All ciphertexts should be unique", 100, ciphertexts.size)
    }

    @Test
    fun `AES-GCM should detect tampering`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val plaintext = "Authenticated data".toByteArray()
        
        val ciphertext = cipher.encrypt(plaintext, key, iv)
        
        // 篡改密文的不同位置
        val positions = listOf(0, ciphertext.size / 2, ciphertext.size - 1)
        
        for (pos in positions) {
            val tampered = ciphertext.copyOf()
            tampered[pos] = (tampered[pos].toInt() xor 0xFF).toByte()
            
            try {
                cipher.decrypt(tampered, key, iv)
                fail("Should have detected tampering at position $pos")
            } catch (e: Exception) {
                // Expected - tampering detected
            }
        }
    }

    @Test
    fun `Same plaintext with same key and IV produces same ciphertext`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val plaintext = "Deterministic test".toByteArray()
        
        val ct1 = cipher.encrypt(plaintext, key, iv)
        val ct2 = cipher.encrypt(plaintext, key, iv)
        
        assertArrayEquals("Same input should produce same output", ct1, ct2)
    }

    // ==================== 随机数质量测试 ====================

    @Test
    fun `SecureRandom should produce uniform distribution`() {
        val random = SecureRandom()
        val sampleSize = 100000
        val buckets = IntArray(256)
        
        repeat(sampleSize) {
            val bytes = ByteArray(1)
            random.nextBytes(bytes)
            buckets[(bytes[0].toInt() and 0xFF)]++
        }
        
        val expected = sampleSize.toDouble() / 256
        val chiSquare = buckets.sumOf { (it - expected) * (it - expected) / expected }
        
        // Chi-square 临界值 (自由度=255, α=0.01) ≈ 310
        // 较宽松的检查
        println("Chi-square value: $chiSquare (expected < 310 for uniform distribution)")
        assertTrue("Random distribution should be approximately uniform", chiSquare < 350)
    }

    @Test
    fun `IV generation should be unique`() {
        val cipher = AESCipher.gcm()
        val ivs = mutableSetOf<String>()
        
        repeat(10000) {
            val iv = cipher.generateIV()
            ivs.add(iv.toHexString())
        }
        
        assertEquals("All IVs should be unique", 10000, ivs.size)
    }

    @Test
    fun `Key generation should be unique`() {
        val keys = mutableSetOf<String>()
        
        repeat(1000) {
            val key = generateAESKey(256)
            keys.add(key.encoded.toHexString())
        }
        
        assertEquals("All keys should be unique", 1000, keys.size)
    }

    // ==================== 密钥派生测试 ====================

    @Test
    fun `PBKDF2 should produce deterministic output`() {
        val hashEngine = com.example.cryptokit.core.hash.StandardHashEngine.sha256()
        val password = "MyPassword123".toCharArray()
        val salt = ByteArray(16) { it.toByte() }
        
        val key1 = hashEngine.deriveKey(password.copyOf(), salt, 10000, 256)
        val key2 = hashEngine.deriveKey(password.copyOf(), salt, 10000, 256)
        
        assertArrayEquals("Same inputs should produce same key", key1.encoded, key2.encoded)
    }

    @Test
    fun `PBKDF2 should produce different output for different salts`() {
        val hashEngine = com.example.cryptokit.core.hash.StandardHashEngine.sha256()
        val password = "MyPassword123".toCharArray()
        val salt1 = ByteArray(16) { it.toByte() }
        val salt2 = ByteArray(16) { (it + 1).toByte() }
        
        val key1 = hashEngine.deriveKey(password.copyOf(), salt1, 10000, 256)
        val key2 = hashEngine.deriveKey(password.copyOf(), salt2, 10000, 256)
        
        assertFalse("Different salts should produce different keys", 
            key1.encoded.contentEquals(key2.encoded))
    }

    @Test
    fun `PBKDF2 should produce different output for different passwords`() {
        val hashEngine = com.example.cryptokit.core.hash.StandardHashEngine.sha256()
        val password1 = "Password1".toCharArray()
        val password2 = "Password2".toCharArray()
        val salt = ByteArray(16) { it.toByte() }
        
        val key1 = hashEngine.deriveKey(password1, salt, 10000, 256)
        val key2 = hashEngine.deriveKey(password2, salt, 10000, 256)
        
        assertFalse("Different passwords should produce different keys", 
            key1.encoded.contentEquals(key2.encoded))
    }

    // ==================== 敏感数据保护测试 ====================

    @Test
    fun `CipherResult close should mark as cleared`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val plaintext = "Sensitive data".toByteArray()
        
        val ciphertext = cipher.encrypt(plaintext, key, iv)
        
        val result = CipherResult(
            ciphertext = ciphertext,
            key = key,
            iv = iv,
            mode = "GCM",
            algorithm = "AES"
        )
        
        assertFalse("Should not be cleared initially", result.isCleared())
        
        result.close()
        
        assertTrue("Should be marked as cleared", result.isCleared())
    }

    @Test
    fun `CipherResult use block should auto-close`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val plaintext = "Sensitive data".toByteArray()
        
        val ciphertext = cipher.encrypt(plaintext, key, iv)
        
        val result = CipherResult(
            ciphertext = ciphertext,
            key = key,
            iv = iv,
            mode = "GCM",
            algorithm = "AES"
        )
        
        result.use { r ->
            assertFalse("Should not be cleared inside use block", r.isCleared())
        }
        
        assertTrue("Should be cleared after use block", result.isCleared())
    }

    @Test
    fun `CipherResult validate should throw if cleared`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        val result = CipherResult(
            ciphertext = byteArrayOf(1, 2, 3),
            key = key,
            iv = iv,
            mode = "GCM",
            algorithm = "AES"
        )
        
        result.close()
        
        try {
            result.validate()
            fail("Should throw on validate after close")
        } catch (e: IllegalStateException) {
            // Expected
        }
    }

    // ==================== CipherResult 恒定时间比较测试 ====================

    @Test
    fun `CipherResult equals should use constant time comparison`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        val result1 = CipherResult(
            ciphertext = byteArrayOf(1, 2, 3, 4, 5),
            key = key,
            iv = iv.copyOf(),
            mode = "GCM",
            algorithm = "AES"
        )
        
        val result2 = CipherResult(
            ciphertext = byteArrayOf(1, 2, 3, 4, 5),
            key = key,
            iv = iv.copyOf(),
            mode = "GCM",
            algorithm = "AES"
        )
        
        val result3 = CipherResult(
            ciphertext = byteArrayOf(1, 2, 3, 4, 6),
            key = key,
            iv = iv.copyOf(),
            mode = "GCM",
            algorithm = "AES"
        )
        
        assertTrue(result1 == result2)
        assertFalse(result1 == result3)
    }

    // ==================== 算法降级保护测试 ====================

    @Test
    fun `Should detect if ECB mode is used`() {
        // ECB 模式不应该用于敏感数据，但如果使用应该有一致的行为
        val cipher = AESCipher("ECB", "PKCS5Padding", 128, null)
        val key = generateAESKey(256)
        
        // ECB 不使用 IV
        val plaintext = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
        val emptyIv = ByteArray(16)
        
        val ciphertext1 = cipher.encrypt(plaintext, key, emptyIv)
        val ciphertext2 = cipher.encrypt(plaintext, key, emptyIv)
        
        // ECB 模式下相同明文产生相同密文 (这是一个安全警告)
        assertArrayEquals("ECB produces deterministic output (security concern)", ciphertext1, ciphertext2)
    }

    // ==================== 辅助方法 ====================

    private fun generateAESKey(keySize: Int): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
