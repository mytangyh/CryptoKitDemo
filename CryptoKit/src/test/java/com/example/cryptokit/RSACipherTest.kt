package com.example.cryptokit

import com.example.cryptokit.core.asymmetric.RSACipher
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom

/**
 * RSA 加密核心单元测试
 */
class RSACipherTest {

    private val testData = "Hello RSA!".toByteArray()

    @Test
    fun `test RSA-OAEP-SHA256 encryption and decryption`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair = generateRSAKeyPair(2048)

        val ciphertext = cipher.encrypt(testData, keyPair.public)
        val decrypted = cipher.decrypt(ciphertext, keyPair.private)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test RSA-OAEP-SHA1 encryption and decryption`() {
        val cipher = RSACipher.oaepSha1()
        val keyPair = generateRSAKeyPair(2048)

        val ciphertext = cipher.encrypt(testData, keyPair.public)
        val decrypted = cipher.decrypt(ciphertext, keyPair.private)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test RSA-PKCS1 encryption and decryption`() {
        val cipher = RSACipher.pkcs1()
        val keyPair = generateRSAKeyPair(2048)

        val ciphertext = cipher.encrypt(testData, keyPair.public)
        val decrypted = cipher.decrypt(ciphertext, keyPair.private)

        assertArrayEquals(testData, decrypted)
    }

    @Test
    fun `test RSA with different key sizes`() {
        val cipher = RSACipher.oaepSha256()
        
        listOf(1024, 2048).forEach { keySize ->
            val keyPair = generateRSAKeyPair(keySize)
            
            val ciphertext = cipher.encrypt(testData, keyPair.public)
            val decrypted = cipher.decrypt(ciphertext, keyPair.private)

            assertArrayEquals("Failed for key size $keySize", testData, decrypted)
        }
    }

    @Test
    fun `test RSA ciphertext size equals key size`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair = generateRSAKeyPair(2048)

        val ciphertext = cipher.encrypt(testData, keyPair.public)
        
        // RSA 输出大小 = 密钥大小 / 8 = 256 字节
        assertEquals(256, ciphertext.size)
    }

    @Test
    fun `test max plaintext size for OAEP-SHA256`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair = generateRSAKeyPair(2048)
        
        // OAEP-SHA256: max = 256 - 66 = 190 bytes
        val maxData = ByteArray(190) { it.toByte() }

        val ciphertext = cipher.encrypt(maxData, keyPair.public)
        val decrypted = cipher.decrypt(ciphertext, keyPair.private)

        assertArrayEquals(maxData, decrypted)
    }

    @Test(expected = Exception::class)
    fun `test plaintext too long throws exception`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair = generateRSAKeyPair(2048)
        
        // OAEP-SHA256: max = 190 bytes, so 200 should fail
        val tooLongData = ByteArray(200) { it.toByte() }

        cipher.encrypt(tooLongData, keyPair.public) // Should throw
    }

    @Test(expected = Exception::class)
    fun `test decryption with wrong key fails`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair1 = generateRSAKeyPair(2048)
        val keyPair2 = generateRSAKeyPair(2048)

        val ciphertext = cipher.encrypt(testData, keyPair1.public)
        cipher.decrypt(ciphertext, keyPair2.private) // Should throw
    }

    @Test
    fun `test same plaintext produces different ciphertexts (OAEP randomness)`() {
        val cipher = RSACipher.oaepSha256()
        val keyPair = generateRSAKeyPair(2048)

        val ciphertext1 = cipher.encrypt(testData, keyPair.public)
        val ciphertext2 = cipher.encrypt(testData, keyPair.public)

        // OAEP uses random padding, so ciphertexts should differ
        assertFalse(ciphertext1.contentEquals(ciphertext2))
    }

    private fun generateRSAKeyPair(keySize: Int): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }
}
