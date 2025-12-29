package com.example.cryptokit

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.keymanager.KeyManagerImpl
import com.example.cryptokit.keymanager.KeyStoreOptions
import org.junit.Assert.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

/**
 * CryptoKit API 集成测试
 * 
 * 在真实 Android 环境中测试完整的加密流程
 */
@RunWith(AndroidJUnit4::class)
class CryptoKitIntegrationTest {

    private val keyManager = KeyManagerImpl.instance
    private val testAliasPrefix = "cryptokit_test_"
    private val testAliases = mutableListOf<String>()

    @Before
    fun setUp() {
        cleanupTestKeys()
    }

    @After
    fun tearDown() {
        cleanupTestKeys()
    }

    private fun cleanupTestKeys() {
        testAliases.forEach { alias ->
            try {
                keyManager.deleteKey(alias)
            } catch (e: Exception) { }
        }
        testAliases.clear()
        
        keyManager.listAliases().filter { it.startsWith(testAliasPrefix) }.forEach { alias ->
            try {
                keyManager.deleteKey(alias)
            } catch (e: Exception) { }
        }
    }

    private fun createTestAlias(suffix: String): String {
        val alias = "${testAliasPrefix}${suffix}_${System.currentTimeMillis()}"
        testAliases.add(alias)
        return alias
    }

    // ==================== AES 加密集成测试 ====================

    @Test
    fun aesBuilder_encryptDecrypt_withGeneratedKey() {
        val testData = "Hello CryptoKit! 你好加密套件！ 🔐"
        
        val result = CryptoKit.aes().encrypt(testData)
        
        assertNotNull("Result should not be null", result)
        assertFalse("Ciphertext should not be empty", result.ciphertext.isEmpty())
        
        val decrypted = CryptoKit.aes().decryptToString(result)
        
        assertEquals("Decrypted should match original", testData, decrypted)
    }

    @Test
    fun aesBuilder_cbc_encryptDecrypt() {
        val testData = "CBC mode test data"
        
        val result = CryptoKit.aes()
            .cbc()
            .encrypt(testData)
        
        assertEquals("Mode should be CBC", "CBC", result.mode)
        
        val decrypted = CryptoKit.aes().decryptToString(result)
        assertEquals(testData, decrypted)
    }

    @Test
    fun aesBuilder_withSharedKey_encryptDecrypt() {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(16) { (it * 2).toByte() }
        val testData = "Shared key test"
        
        val ciphertext = CryptoKit.encryptAES(testData, key, iv)
        val decrypted = CryptoKit.decryptAES(ciphertext, key, iv)
        
        assertEquals(testData, decrypted)
    }

    // ==================== RSA 加密集成测试 ====================

    @Test
    fun rsaBuilder_encryptDecrypt() {
        val keyPair = CryptoKit.rsa().generateKeyPair()
        val testData = "RSA test data"
        
        val ciphertext = CryptoKit.rsa()
            .publicKey(keyPair.public)
            .encrypt(testData)
        
        val decrypted = CryptoKit.rsa()
            .privateKey(keyPair.private)
            .decryptToString(ciphertext)
        
        assertEquals(testData, decrypted)
    }

    @Test
    fun rsaBuilder_signAndVerify() {
        val keyPair = CryptoKit.rsa().generateKeyPair()
        val testData = "Data to sign"
        
        val signature = CryptoKit.rsa()
            .privateKey(keyPair.private)
            .sign(testData)
        
        val isValid = CryptoKit.rsa()
            .publicKey(keyPair.public)
            .verify(testData, signature)
        
        assertTrue("Signature should verify", isValid)
    }

    // ==================== ECC 集成测试 ====================

    @Test
    fun eccBuilder_signAndVerify() {
        val keyPair = CryptoKit.ecc().p256().generateKeyPair()
        val testData = "ECDSA test data"
        
        val signature = CryptoKit.ecc()
            .privateKey(keyPair.private)
            .sign(testData)
        
        val isValid = CryptoKit.ecc()
            .publicKey(keyPair.public)
            .verify(testData, signature)
        
        assertTrue("ECDSA signature should verify", isValid)
    }

    // ==================== Hybrid 加密集成测试 ====================

    @Test
    fun hybridBuilder_encryptDecrypt_largeData() {
        val keyPair = CryptoKit.rsa().generateKeyPair()
        val largeData = ByteArray(100 * 1024) { (it % 256).toByte() } // 100KB
        
        val result = CryptoKit.hybrid()
            .publicKey(keyPair.public)
            .encrypt(largeData)
        
        assertNotNull("Result should not be null", result)
        
        val decrypted = CryptoKit.hybrid()
            .privateKey(keyPair.private)
            .decrypt(result)
        
        assertArrayEquals("Decrypted should match original", largeData, decrypted)
    }

    // ==================== Hash 集成测试 ====================

    @Test
    fun hash_sha256_producesConsistentResult() {
        val testData = "Hash test data"
        
        val hash1 = CryptoKit.sha256(testData)
        val hash2 = CryptoKit.sha256(testData)
        
        assertEquals("Hashes should be consistent", hash1, hash2)
        assertEquals("SHA-256 should produce 64 hex chars", 64, hash1.length)
    }

    @Test
    fun hash_hmac_producesCorrectOutput() {
        val testData = "HMAC test data"
        val key = ByteArray(32) { it.toByte() }
        
        val hmac1 = CryptoKit.hmacToHex(testData, key)
        val hmac2 = CryptoKit.hmacToHex(testData, key)
        
        assertEquals("HMACs should be consistent", hmac1, hmac2)
    }

    // ==================== KeyStore 集成测试 ====================

    @Test
    fun keyManager_generateAndUseKey() {
        val alias = createTestAlias("integration")
        val testData = "KeyStore integration test".toByteArray()
        
        // 生成密钥
        val key = keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
        
        // 使用密钥加密
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(testData)
        
        // 从 KeyStore 获取密钥并解密
        val retrievedKey = keyManager.getKey(alias)
        assertNotNull("Should retrieve key", retrievedKey)
        
        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher.init(Cipher.DECRYPT_MODE, retrievedKey, GCMParameterSpec(128, iv))
        val decrypted = decryptCipher.doFinal(ciphertext)
        
        assertArrayEquals("Decrypted should match", testData, decrypted)
    }

    // ==================== 编码解码测试 ====================

    @Test
    fun encode_base64_roundtrip() {
        val testData = "Base64 test data 测试数据".toByteArray()
        
        val encoded = CryptoKit.encode.toBase64(testData)
        val decoded = CryptoKit.encode.fromBase64(encoded)
        
        assertArrayEquals(testData, decoded)
    }

    @Test
    fun encode_hex_roundtrip() {
        val testData = byteArrayOf(0x00, 0x11, 0x22, 0x33, 0xFF.toByte())
        
        val encoded = CryptoKit.encode.toHex(testData)
        val decoded = CryptoKit.encode.fromHex(encoded)
        
        assertEquals("0011223ff", encoded.lowercase())
        assertArrayEquals(testData, decoded)
    }

    // ==================== 安全工具测试 ====================

    @Test
    fun secureUtils_wipe_clearsSensitiveData() {
        val sensitiveData = byteArrayOf(1, 2, 3, 4, 5)
        
        CryptoKit.secure.wipe(sensitiveData)
        
        assertTrue("Data should be wiped", sensitiveData.all { it == 0.toByte() })
    }

    @Test
    fun secureUtils_constantTimeEquals_works() {
        val a = byteArrayOf(1, 2, 3, 4, 5)
        val b = byteArrayOf(1, 2, 3, 4, 5)
        val c = byteArrayOf(1, 2, 3, 4, 6)
        
        assertTrue(CryptoKit.secure.constantTimeEquals(a, b))
        assertFalse(CryptoKit.secure.constantTimeEquals(a, c))
    }

    // ==================== PBKDF2 测试 ====================

    @Test
    fun deriveKey_producesConsistentOutput() {
        val password = "MySecurePassword"
        val salt = CryptoKit.secureRandom(16)
        
        val key1 = CryptoKit.deriveKey(password, salt)
        val key2 = CryptoKit.deriveKey(password, salt)
        
        assertArrayEquals("Derived keys should be consistent", key1, key2)
    }

    @Test
    fun deriveKey_differentSalts_produceDifferentKeys() {
        val password = "MySecurePassword"
        val salt1 = CryptoKit.secureRandom(16)
        val salt2 = CryptoKit.secureRandom(16)
        
        val key1 = CryptoKit.deriveKey(password, salt1)
        val key2 = CryptoKit.deriveKey(password, salt2)
        
        assertFalse("Different salts should produce different keys", key1.contentEquals(key2))
    }

    // ==================== 性能测试 ====================

    @Test
    fun performance_aesGcm_acceptableLatency() {
        val testData = ByteArray(1024) { (it % 256).toByte() } // 1KB
        val iterations = 100
        
        // 预热
        repeat(10) {
            val result = CryptoKit.aes().encrypt(testData)
            CryptoKit.aes().decrypt(result)
        }
        
        val startTime = SystemClock.elapsedRealtimeNanos()
        
        repeat(iterations) {
            val result = CryptoKit.aes().encrypt(testData)
            CryptoKit.aes().decrypt(result)
        }
        
        val durationMs = (SystemClock.elapsedRealtimeNanos() - startTime) / 1_000_000.0
        val avgLatency = durationMs / iterations
        
        println("AES-GCM 1KB avg latency: ${String.format("%.3f", avgLatency)}ms")
        
        // 单次操作应该在 10ms 以内
        assertTrue("AES latency should be acceptable", avgLatency < 10.0)
    }

    // ==================== 错误处理测试 ====================

    @Test
    fun aes_decryptWithWrongKey_fails() {
        val result = CryptoKit.aes().encrypt("Test data")
        
        try {
            // 使用新密钥尝试解密
            val wrongKey = KeyGenerator.getInstance("AES").apply { 
                init(256, SecureRandom()) 
            }.generateKey()
            
            CryptoKit.aes()
                .key(wrongKey)
                .iv(result.iv)
                .mode(result.mode)
                .decrypt(result.ciphertext)
            
            fail("Should throw on wrong key")
        } catch (e: Exception) {
            // Expected
        }
    }

    // ==================== 流式加密测试 ====================

    @Test
    fun streamCipher_encryptDecrypt() {
        val testData = ByteArray(10240) { (it % 256).toByte() } // 10KB
        val key = CryptoKit.aes().generateKey()
        val iv = CryptoKit.secureRandom(16)
        
        val encryptedStream = java.io.ByteArrayOutputStream()
        val inputStream = java.io.ByteArrayInputStream(testData)
        
        CryptoKit.stream.encrypt(inputStream, encryptedStream, key, iv, "CBC")
        
        val decryptedStream = java.io.ByteArrayOutputStream()
        val encryptedInput = java.io.ByteArrayInputStream(encryptedStream.toByteArray())
        
        CryptoKit.stream.decrypt(encryptedInput, decryptedStream, key, iv, "CBC")
        
        assertArrayEquals("Stream decryption should match", testData, decryptedStream.toByteArray())
    }
}
