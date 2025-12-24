package com.example.cryptokit

import com.example.cryptokit.core.symmetric.AESCipher
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.KeyGenerator
import java.security.SecureRandom

/**
 * AES 加密核心单元测试
 */
class AESCipherTest {

    private val testData = "Hello, CryptoKit! 你好，加密套件！".toByteArray()

    @Test
    fun `test AES-GCM encryption and decryption`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test AES-CBC encryption and decryption`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test AES-CTR encryption and decryption`() {
        val cipher = AESCipher.ctr()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test AES with different key sizes`() {
        val cipher = AESCipher.gcm()
        
        listOf(128, 192, 256).forEach { keySize ->
            val key = generateAESKey(keySize)
            val iv = cipher.generateIV()

            val ciphertext = cipher.encrypt(testData, key, iv)
            val decrypted = cipher.decrypt(ciphertext, key, iv)

            assertArrayEquals("Failed for key size $keySize", testData, decrypted)
        }
    }

    @Test
    fun `test GCM ciphertext is larger than plaintext`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv)
        
        // GCM 模式输出 = 明文 + 16字节认证标签
        assertTrue(ciphertext.size >= testData.size + 16)
    }

    @Test
    fun `test different IVs produce different ciphertexts`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv1 = cipher.generateIV()
        val iv2 = cipher.generateIV()

        val ciphertext1 = cipher.encrypt(testData, key, iv1)
        val ciphertext2 = cipher.encrypt(testData, key, iv2)

        assertFalse("Same IV used", iv1.contentEquals(iv2))
        assertFalse("Ciphertexts should differ", ciphertext1.contentEquals(ciphertext2))
    }

    @Test
    fun `test empty data encryption`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val emptyData = ByteArray(0)

        val ciphertext = cipher.encrypt(emptyData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(emptyData, decrypted)
    }

    @Test
    fun `test large data encryption`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()
        val largeData = ByteArray(1024 * 1024) { (it % 256).toByte() } // 1MB

        val ciphertext = cipher.encrypt(largeData, key, iv)
        val decrypted = cipher.decrypt(ciphertext, key, iv)

        assertArrayEquals(largeData, decrypted)
    }

    @Test(expected = Exception::class)
    fun `test decryption with wrong key fails`() {
        val cipher = AESCipher.gcm()
        val key1 = generateAESKey(256)
        val key2 = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key1, iv)
        cipher.decrypt(ciphertext, key2, iv) // Should throw
    }

    @Test(expected = Exception::class)
    fun `test decryption with wrong IV fails for GCM`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv1 = cipher.generateIV()
        val iv2 = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv1)
        cipher.decrypt(ciphertext, key, iv2) // Should throw (GCM auth fails)
    }

    @Test(expected = Exception::class)
    fun `test tampered ciphertext fails for GCM`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val iv = cipher.generateIV()

        val ciphertext = cipher.encrypt(testData, key, iv)
        // Tamper with ciphertext
        ciphertext[ciphertext.size / 2] = (ciphertext[ciphertext.size / 2].toInt() xor 0xFF).toByte()
        
        cipher.decrypt(ciphertext, key, iv) // Should throw (GCM auth fails)
    }

    private fun generateAESKey(keySize: Int): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }
}
