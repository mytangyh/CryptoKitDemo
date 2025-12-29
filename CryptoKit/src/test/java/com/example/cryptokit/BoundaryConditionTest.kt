package com.example.cryptokit

import com.example.cryptokit.api.builders.AESBuilder
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.exception.ValidationException
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.KeyGenerator

/**
 * 边界条件测试套件
 * 
 * 金融级测试要求：
 * - 空输入处理
 * - 超大输入处理
 * - 特殊字符/二进制数据处理
 * - 边界值测试
 * - 无效输入拒绝
 */
class BoundaryConditionTest {

    // ==================== 空输入测试 ====================

    @Test
    fun `AES-GCM should handle empty plaintext`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val emptyData = ByteArray(0)

        val ciphertext = cipher.encrypt(emptyData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(emptyData, decrypted)
        // GCM 空明文仍应产生认证标签
        assertTrue("Empty plaintext should still produce auth tag", ciphertext.size >= 16)
    }

    @Test
    fun `AES-CBC should handle empty plaintext`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val emptyData = ByteArray(0)

        val ciphertext = cipher.encrypt(emptyData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(emptyData, decrypted)
    }

    @Test
    fun `Hash should handle empty input`() {
        val hashEngine = StandardHashEngine.sha256()
        val emptyHash = hashEngine.hash(ByteArray(0))
        
        // SHA-256 空输入的已知结果
        val expectedEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assertEquals(expectedEmptyHash, emptyHash.toHexString())
    }

    @Test
    fun `HMAC should handle empty data with valid key`() {
        val hashEngine = StandardHashEngine.sha256()
        val key = ByteArray(32) { it.toByte() }
        val emptyHmac = hashEngine.hmac(ByteArray(0), key)
        
        assertNotNull(emptyHmac)
        assertEquals(32, emptyHmac.size) // SHA-256 output
    }

    // ==================== 超大输入测试 ====================

    @Test
    fun `AES-GCM should handle 10MB data`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 10MB 数据
        val largeData = ByteArray(10 * 1024 * 1024) { (it % 256).toByte() }
        
        val startTime = System.currentTimeMillis()
        val ciphertext = cipher.encrypt(largeData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        val duration = System.currentTimeMillis() - startTime
        
        assertArrayEquals(largeData, decrypted)
        println("10MB AES-GCM encrypt+decrypt took ${duration}ms")
    }

    @Test
    fun `AES-CBC should handle 50MB data`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 50MB 数据
        val largeData = ByteArray(50 * 1024 * 1024) { (it % 256).toByte() }
        
        val startTime = System.currentTimeMillis()
        val ciphertext = cipher.encrypt(largeData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        val duration = System.currentTimeMillis() - startTime
        
        assertArrayEquals(largeData, decrypted)
        println("50MB AES-CBC encrypt+decrypt took ${duration}ms")
    }

    @Test
    fun `Hash should handle 100MB streaming data`() {
        val hashEngine = StandardHashEngine.sha256()
        
        // 100MB 数据
        val largeData = ByteArray(100 * 1024 * 1024) { (it % 256).toByte() }
        
        val startTime = System.currentTimeMillis()
        val hash = hashEngine.hash(largeData)
        val duration = System.currentTimeMillis() - startTime
        
        assertNotNull(hash)
        assertEquals(32, hash.size)
        println("100MB SHA-256 hash took ${duration}ms")
    }

    // ==================== 特殊字符/二进制数据测试 ====================

    @Test
    fun `AES should handle binary data with all byte values`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 包含所有可能字节值的数据 (0x00 - 0xFF)
        val allBytesData = ByteArray(256) { it.toByte() }
        
        val ciphertext = cipher.encrypt(allBytesData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        
        assertArrayEquals(allBytesData, decrypted)
    }

    @Test
    fun `AES should handle NULL bytes embedded in data`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 数据中包含 NULL 字节
        val dataWithNulls = byteArrayOf(0, 1, 2, 0, 0, 3, 4, 0, 5, 0, 0, 0)
        
        val ciphertext = cipher.encrypt(dataWithNulls, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        
        assertArrayEquals(dataWithNulls, decrypted)
    }

    @Test
    fun `AES should handle unicode special characters`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 包含各种 Unicode 特殊字符
        val specialChars = """
            中文测试 日本語テスト 한국어테스트
            Emoji: 😀🎉🔐💰📊
            Special: ™®©℃℉∞≠≈
            Math: ∑∏∫∂∇
            Currency: €£¥₹₽₿
            Control chars: 	 (tab, newline, space variants)
            Zero-width: ​‌‍ (zero-width space, non-joiner, joiner)
        """.trimIndent().toByteArray(Charsets.UTF_8)
        
        val ciphertext = cipher.encrypt(specialChars, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        
        assertArrayEquals(specialChars, decrypted)
        assertEquals(String(specialChars, Charsets.UTF_8), String(decrypted, Charsets.UTF_8))
    }

    @Test
    fun `AES should handle high entropy random data`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 高熵随机数据 (模拟已加密数据再加密)
        val randomData = ByteArray(4096)
        SecureRandom().nextBytes(randomData)
        
        val ciphertext = cipher.encrypt(randomData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        
        assertArrayEquals(randomData, decrypted)
    }

    // ==================== 边界值测试 ====================

    @Test
    fun `AES should handle single byte data`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        val singleByte = byteArrayOf(0x42)
        
        val ciphertext = cipher.encrypt(singleByte, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)
        
        assertArrayEquals(singleByte, decrypted)
    }

    @Test
    fun `AES-CBC should handle block boundary data`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        // 测试各种块边界大小 (AES 块大小 = 16 字节)
        val blockSizes = listOf(15, 16, 17, 31, 32, 33, 48, 64, 127, 128, 129)
        
        blockSizes.forEach { size ->
            val data = ByteArray(size) { (it % 256).toByte() }
            val ciphertext = cipher.encrypt(data, key, iv)
            val decrypted = cipher.decrypt(ciphertext, key, iv)
            assertArrayEquals("Failed for size $size", data, decrypted)
        }
    }

    @Test
    fun `RSA should handle maximum plaintext length`() {
        val rsaCipher = RSACipher.oaepSha256()
        val keyPair = rsaCipher.generateKeyPair(2048)
        
        // RSA-2048 with OAEP-SHA256 最大明文 = 2048/8 - 2*256/8 - 2 = 190 字节
        val maxPlaintext = ByteArray(190) { (it % 256).toByte() }
        
        val ciphertext = rsaCipher.encrypt(maxPlaintext, keyPair.public)
        val decrypted = rsaCipher.decrypt(ciphertext, keyPair.private)
        
        assertArrayEquals(maxPlaintext, decrypted)
    }

    @Test(expected = Exception::class)
    fun `RSA should reject plaintext exceeding maximum length`() {
        val rsaCipher = RSACipher.oaepSha256()
        val keyPair = rsaCipher.generateKeyPair(2048)
        
        // 超过最大长度
        val tooLargePlaintext = ByteArray(191) { (it % 256).toByte() }
        
        rsaCipher.encrypt(tooLargePlaintext, keyPair.public) // Should throw
    }

    // ==================== 无效输入拒绝测试 ====================

    @Test(expected = Exception::class)
    fun `AES should reject invalid key size`() {
        val cipher = AESCipher.gcm()
        val invalidKey = javax.crypto.spec.SecretKeySpec(ByteArray(15), "AES") // 120 bits - invalid
        val iv = cipher.generateIV()
        
        cipher.encrypt(byteArrayOf(1, 2, 3), invalidKey, iv) // Should throw
    }

    @Test
    fun `AES-GCM should work with various IV sizes`() {
        // GCM 实际上支持任意长度的 IV（NIST 规范），但推荐使用 12 字节
        // 此测试验证非标准 IV 大小仍然能正常工作
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val testData = byteArrayOf(1, 2, 3)
        
        // 标准 12 字节 IV
        val standardIv = ByteArray(12) { it.toByte() }
        val ct1 = cipher.encrypt(testData, key, standardIv)
        val pt1 = cipher.decrypt(ct1, key, standardIv)
        assertArrayEquals(testData, pt1)
        
        // 非标准 16 字节 IV（仍然能工作，但效率较低）
        val nonStandardIv = ByteArray(16) { it.toByte() }
        val ct2 = cipher.encrypt(testData, key, nonStandardIv)
        val pt2 = cipher.decrypt(ct2, key, nonStandardIv)
        assertArrayEquals(testData, pt2)
        
        // 确认不同 IV 产生不同密文
        assertFalse("Different IVs should produce different ciphertext", ct1.contentEquals(ct2))
    }

    @Test(expected = Exception::class)
    fun `AES-CBC should reject truncated ciphertext`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        
        val plaintext = "Hello World".toByteArray()
        val ciphertext = cipher.encrypt(plaintext, key, iv)
        
        // 截断密文
        val truncatedCiphertext = ciphertext.copyOf(ciphertext.size - 5)
        
        cipher.decrypt(truncatedCiphertext, key, iv) // Should throw
    }

    @Test
    fun `Hash should produce consistent output for same input`() {
        val hashEngine = StandardHashEngine.sha256()
        val input = "Consistent hash test data".toByteArray()
        
        val hash1 = hashEngine.hash(input)
        val hash2 = hashEngine.hash(input)
        val hash3 = hashEngine.hash(input)
        
        assertArrayEquals(hash1, hash2)
        assertArrayEquals(hash2, hash3)
    }

    @Test
    fun `Hash should produce different output for slightly different input`() {
        val hashEngine = StandardHashEngine.sha256()
        
        val input1 = "Test data A".toByteArray()
        val input2 = "Test data B".toByteArray()
        
        val hash1 = hashEngine.hash(input1)
        val hash2 = hashEngine.hash(input2)
        
        assertFalse(hash1.contentEquals(hash2))
    }

    // ==================== 辅助方法 ====================

    private fun generateAESKey(keySize: Int): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
}
