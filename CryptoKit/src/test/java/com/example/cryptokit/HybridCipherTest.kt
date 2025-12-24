package com.example.cryptokit

import com.example.cryptokit.core.hybrid.RSAAESHybridCipher
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.symmetric.AESCipher
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom

/**
 * 混合加密单元测试
 */
class HybridCipherTest {

    private val testData = "Hello, Hybrid Encryption! 你好，混合加密！".toByteArray()

    @Test
    fun `test hybrid encryption and decryption`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair = generateRSAKeyPair(2048)

        val result = cipher.encrypt(testData, keyPair.public)
        val decrypted = cipher.decrypt(result, keyPair.private)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test hybrid encryption result components`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair = generateRSAKeyPair(2048)

        val result = cipher.encrypt(testData, keyPair.public)

        // 加密后的AES密钥大小应该等于RSA密钥大小/8
        assertEquals(256, result.encryptedKey.size)
        // IV 应该是 12 字节 (GCM)
        assertEquals(12, result.iv.size)
        // 密文至少包含原始数据 + GCM tag
        assertTrue(result.ciphertext.size >= testData.size)
    }

    @Test
    fun `test hybrid can encrypt large data`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair = generateRSAKeyPair(2048)
        
        // 1MB 数据 - 这对纯 RSA 是不可能的
        val largeData = ByteArray(1024 * 1024) { (it % 256).toByte() }

        val result = cipher.encrypt(largeData, keyPair.public)
        val decrypted = cipher.decrypt(result, keyPair.private)

        assertArrayEquals(largeData, decrypted)
    }

    @Test
    fun `test hybrid with different AES key sizes`() {
        val keyPair = generateRSAKeyPair(2048)
        
        listOf(128, 192, 256).forEach { aesKeySize ->
            val cipher = RSAAESHybridCipher(
                RSACipher.oaepSha256(),
                AESCipher.gcm(),
                aesKeySize
            )
            
            val result = cipher.encrypt(testData, keyPair.public)
            val decrypted = cipher.decrypt(result, keyPair.private)
            
            assertArrayEquals("Failed for AES-$aesKeySize", testData, decrypted)
        }
    }

    @Test
    fun `test hybrid produces different ciphertexts for same plaintext`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair = generateRSAKeyPair(2048)

        val result1 = cipher.encrypt(testData, keyPair.public)
        val result2 = cipher.encrypt(testData, keyPair.public)

        // 由于随机 AES 密钥和 IV，密文应该不同
        assertFalse(result1.ciphertext.contentEquals(result2.ciphertext))
        assertFalse(result1.encryptedKey.contentEquals(result2.encryptedKey))
        assertFalse(result1.iv.contentEquals(result2.iv))
    }

    @Test(expected = Exception::class)
    fun `test hybrid decryption with wrong key fails`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair1 = generateRSAKeyPair(2048)
        val keyPair2 = generateRSAKeyPair(2048)

        val result = cipher.encrypt(testData, keyPair1.public)
        cipher.decrypt(result, keyPair2.private) // Should throw
    }

    @Test
    fun `test hybrid with empty data`() {
        val cipher = RSAAESHybridCipher.default()
        val keyPair = generateRSAKeyPair(2048)
        val emptyData = ByteArray(0)

        val result = cipher.encrypt(emptyData, keyPair.public)
        val decrypted = cipher.decrypt(result, keyPair.private)

        assertArrayEquals(emptyData, decrypted)
    }

    private fun generateRSAKeyPair(keySize: Int): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }
}
