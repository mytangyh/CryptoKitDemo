package com.example.cryptokit

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.cryptokit.keymanager.KeyManagerImpl
import com.example.cryptokit.keymanager.KeyStoreOptions
import org.junit.Assert.*
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AndroidKeyStore 集成测试
 * 
 * 金融级测试要求：
 * - KeyStore 初始化和可用性
 * - AES/RSA/EC 密钥生成
 * - 密钥持久化验证
 * - 密钥属性验证
 * - KeyStore 并发访问
 * - StrongBox 支持检测
 * 
 * 注意：这些测试必须在真实设备或模拟器上运行 (instrumented test)
 */
@RunWith(AndroidJUnit4::class)
class KeyStoreInstrumentedTest {

    private val keyManager = KeyManagerImpl.instance
    private val testAliasPrefix = "test_key_"
    private val testAliases = mutableListOf<String>()

    @Before
    fun setUp() {
        // 清理之前的测试密钥
        cleanupTestKeys()
    }

    @After
    fun tearDown() {
        // 清理测试密钥
        cleanupTestKeys()
    }

    private fun cleanupTestKeys() {
        testAliases.forEach { alias ->
            try {
                keyManager.deleteKey(alias)
            } catch (e: Exception) {
                // 忽略清理错误
            }
        }
        testAliases.clear()
        
        // 额外清理遗留的测试密钥
        keyManager.listAliases().filter { it.startsWith(testAliasPrefix) }.forEach { alias ->
            try {
                keyManager.deleteKey(alias)
            } catch (e: Exception) {
                // 忽略
            }
        }
    }

    private fun createTestAlias(suffix: String): String {
        val alias = "${testAliasPrefix}${suffix}_${System.currentTimeMillis()}"
        testAliases.add(alias)
        return alias
    }

    // ==================== KeyStore 可用性测试 ====================

    @Test
    fun keyStore_isAvailable() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        assertNotNull("KeyStore should be available", keyStore)
    }

    @Test
    fun keyManager_canListAliases() {
        val aliases = keyManager.listAliases()
        assertNotNull("Should return alias list", aliases)
    }

    // ==================== AES 密钥生成测试 ====================

    @Test
    fun generateAESKey_256bit_succeeds() {
        val alias = createTestAlias("aes256")
        
        val key = keyManager.generateAESKeyInKeystore(
            alias = alias,
            keySize = 256,
            options = KeyStoreOptions.standard()
        )
        
        assertNotNull("Key should be generated", key)
        assertEquals("AES", key.algorithm)
        assertTrue("Key should exist in keystore", keyManager.containsAlias(alias))
    }

    @Test
    fun generateAESKey_128bit_succeeds() {
        val alias = createTestAlias("aes128")
        
        val key = keyManager.generateAESKeyInKeystore(
            alias = alias,
            keySize = 128,
            options = KeyStoreOptions.standard()
        )
        
        assertNotNull("Key should be generated", key)
        assertEquals("AES", key.algorithm)
    }

    @Test
    fun generateAESKey_canEncryptAndDecrypt() {
        val alias = createTestAlias("aes_encrypt")
        val testData = "Hello AndroidKeyStore!".toByteArray()
        
        val key = keyManager.generateAESKeyInKeystore(
            alias = alias,
            keySize = 256,
            options = KeyStoreOptions.standard()
        )
        
        // 加密
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(testData)
        
        // 解密
        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        val decrypted = decryptCipher.doFinal(ciphertext)
        
        assertArrayEquals("Decrypted should match original", testData, decrypted)
    }

    @Test
    fun generateAESKey_retrieveExistingKey() {
        val alias = createTestAlias("aes_retrieve")
        
        // 生成密钥
        val originalKey = keyManager.generateAESKeyInKeystore(
            alias = alias,
            keySize = 256,
            options = KeyStoreOptions.standard()
        )
        
        // 获取密钥
        val retrievedKey = keyManager.getKey(alias) as? SecretKey
        
        assertNotNull("Should retrieve key", retrievedKey)
        assertEquals("AES", retrievedKey?.algorithm)
    }

    // ==================== RSA 密钥对生成测试 ====================

    @Test
    fun generateRSAKeyPair_2048bit_succeeds() {
        val alias = createTestAlias("rsa2048")
        
        val keyPair = keyManager.generateRSAKeyPairInKeystore(
            alias = alias,
            keySize = 2048,
            options = KeyStoreOptions.standard()
        )
        
        assertNotNull("KeyPair should be generated", keyPair)
        assertNotNull("Public key should exist", keyPair.public)
        assertNotNull("Private key should exist", keyPair.private)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun generateRSAKeyPair_4096bit_succeeds() {
        val alias = createTestAlias("rsa4096")
        
        val keyPair = keyManager.generateRSAKeyPairInKeystore(
            alias = alias,
            keySize = 4096,
            options = KeyStoreOptions.standard()
        )
        
        assertNotNull("KeyPair should be generated", keyPair)
        assertEquals("RSA", keyPair.public.algorithm)
    }

    @Test
    fun generateRSAKeyPair_canEncryptAndDecrypt() {
        val alias = createTestAlias("rsa_encrypt")
        val testData = "RSA test data".toByteArray()
        
        val keyPair = keyManager.generateRSAKeyPairInKeystore(
            alias = alias,
            keySize = 2048,
            options = KeyStoreOptions.standard()
        )
        
        // 加密
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
        val ciphertext = cipher.doFinal(testData)
        
        // 解密
        val decryptCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.private)
        val decrypted = decryptCipher.doFinal(ciphertext)
        
        assertArrayEquals("Decrypted should match original", testData, decrypted)
    }

    @Test
    fun generateRSAKeyPair_canSignAndVerify() {
        val alias = createTestAlias("rsa_sign")
        val testData = "Data to sign".toByteArray()
        
        val keyPair = keyManager.generateRSAKeyPairInKeystore(
            alias = alias,
            keySize = 2048,
            options = KeyStoreOptions.standard()
        )
        
        // 签名
        val signature = java.security.Signature.getInstance("SHA256withRSA")
        signature.initSign(keyPair.private)
        signature.update(testData)
        val signatureBytes = signature.sign()
        
        // 验签
        val verifySignature = java.security.Signature.getInstance("SHA256withRSA")
        verifySignature.initVerify(keyPair.public)
        verifySignature.update(testData)
        val isValid = verifySignature.verify(signatureBytes)
        
        assertTrue("Signature should verify", isValid)
    }

    // ==================== EC 密钥对生成测试 ====================

    @Test
    fun generateECKeyPair_succeeds() {
        val alias = createTestAlias("ec")
        
        val keyPair = keyManager.generateECKeyPairInKeystore(
            alias = alias,
            options = KeyStoreOptions.standard()
        )
        
        assertNotNull("KeyPair should be generated", keyPair)
        assertNotNull("Public key should exist", keyPair.public)
        assertNotNull("Private key should exist", keyPair.private)
        assertEquals("EC", keyPair.public.algorithm)
    }

    @Test
    fun generateECKeyPair_canSignAndVerify() {
        val alias = createTestAlias("ec_sign")
        val testData = "ECDSA test data".toByteArray()
        
        val keyPair = keyManager.generateECKeyPairInKeystore(
            alias = alias,
            options = KeyStoreOptions.standard()
        )
        
        // 签名
        val signature = java.security.Signature.getInstance("SHA256withECDSA")
        signature.initSign(keyPair.private)
        signature.update(testData)
        val signatureBytes = signature.sign()
        
        // 验签
        val verifySignature = java.security.Signature.getInstance("SHA256withECDSA")
        verifySignature.initVerify(keyPair.public)
        verifySignature.update(testData)
        val isValid = verifySignature.verify(signatureBytes)
        
        assertTrue("ECDSA signature should verify", isValid)
    }

    // ==================== 密钥管理测试 ====================

    @Test
    fun deleteKey_removesKey() {
        val alias = createTestAlias("delete_test")
        
        keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
        assertTrue("Key should exist before delete", keyManager.containsAlias(alias))
        
        val deleted = keyManager.deleteKey(alias)
        
        assertTrue("Delete should return true", deleted)
        assertFalse("Key should not exist after delete", keyManager.containsAlias(alias))
        
        // 从清理列表移除
        testAliases.remove(alias)
    }

    @Test
    fun containsAlias_returnsFalseForNonexistent() {
        val alias = "nonexistent_key_${System.currentTimeMillis()}"
        
        assertFalse("Should return false for nonexistent key", keyManager.containsAlias(alias))
    }

    @Test
    fun getKey_returnsNullForNonexistent() {
        val alias = "nonexistent_key_${System.currentTimeMillis()}"
        
        val key = keyManager.getKey(alias)
        
        assertNull("Should return null for nonexistent key", key)
    }

    @Test
    fun getKeyPair_returnsNullForNonexistent() {
        val alias = "nonexistent_keypair_${System.currentTimeMillis()}"
        
        val keyPair = keyManager.getKeyPair(alias)
        
        assertNull("Should return null for nonexistent keypair", keyPair)
    }

    // ==================== 密钥持久化测试 ====================

    @Test
    fun keyPersistence_survivesCacheRefresh() {
        val alias = createTestAlias("persist")
        
        // 生成密钥
        keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
        
        // 刷新 KeyStore（模拟应用重启）
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        // 验证密钥仍然存在
        assertTrue("Key should persist", keyManager.containsAlias(alias))
        
        val key = keyManager.getKey(alias)
        assertNotNull("Should retrieve persisted key", key)
    }

    // ==================== 金融级安全配置测试 ====================

    @Test
    fun financialGradeOptions_createsValidConfig() {
        val options = KeyStoreOptions.financialGrade()
        
        assertTrue("Should require user authentication", options.requireUserAuthentication)
        assertTrue("Should require biometric", options.requireBiometric)
        assertTrue("Should use StrongBox if available", options.isStrongBoxBacked)
        assertTrue("Should require unlocked device", options.requireUnlockedDevice)
    }

    // 注意：需要生物认证的测试无法自动运行，需要手动测试
    // @Test
    // fun generateKey_withBiometricAuth_requiresAuth() { ... }

    // ==================== StrongBox 支持测试 ====================

    @Test
    fun strongBoxSupport_canBeDetected() {
        val isSupported = keyManager.isStrongBoxSupported()
        
        // 只验证方法可以调用，实际支持取决于设备
        println("StrongBox supported: $isSupported")
        
        // Android 9+ 才支持 StrongBox
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val sdkVersion = android.os.Build.VERSION.SDK_INT
        
        if (sdkVersion < android.os.Build.VERSION_CODES.P) {
            assertFalse("StrongBox not supported before Android 9", isSupported)
        }
        // 对于 Android 9+，支持与否取决于硬件
    }

    // ==================== 并发访问测试 ====================

    @Test
    fun concurrentKeyGeneration_succeeds() {
        val threadCount = 5
        val keysPerThread = 3
        val latch = java.util.concurrent.CountDownLatch(threadCount)
        val errors = java.util.concurrent.atomic.AtomicInteger(0)
        
        repeat(threadCount) { threadId ->
            Thread {
                try {
                    repeat(keysPerThread) { keyId ->
                        val alias = createTestAlias("concurrent_${threadId}_$keyId")
                        synchronized(testAliases) {
                            testAliases.add(alias)
                        }
                        keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }.start()
        }
        
        latch.await(60, java.util.concurrent.TimeUnit.SECONDS)
        
        assertEquals("Should have no errors", 0, errors.get())
    }

    @Test
    fun concurrentKeyAccess_succeeds() {
        val alias = createTestAlias("concurrent_access")
        val testData = "Concurrent test data".toByteArray()
        
        // 先生成密钥
        keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
        
        val threadCount = 10
        val operationsPerThread = 20
        val latch = java.util.concurrent.CountDownLatch(threadCount)
        val errors = java.util.concurrent.atomic.AtomicInteger(0)
        val successCount = java.util.concurrent.atomic.AtomicInteger(0)
        
        repeat(threadCount) {
            Thread {
                try {
                    repeat(operationsPerThread) {
                        val key = keyManager.getKey(alias) as SecretKey
                        
                        // 加密
                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(Cipher.ENCRYPT_MODE, key)
                        val iv = cipher.iv
                        val ciphertext = cipher.doFinal(testData)
                        
                        // 解密
                        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
                        decryptCipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                        val decrypted = decryptCipher.doFinal(ciphertext)
                        
                        if (testData.contentEquals(decrypted)) {
                            successCount.incrementAndGet()
                        } else {
                            errors.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errors.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }.start()
        }
        
        latch.await(120, java.util.concurrent.TimeUnit.SECONDS)
        
        assertEquals("Should have no errors", 0, errors.get())
        assertEquals("All operations should succeed", 
            threadCount * operationsPerThread, successCount.get())
    }

    // ==================== 错误处理测试 ====================

    @Test(expected = IllegalArgumentException::class)
    fun generateAESKey_blankAlias_throws() {
        keyManager.generateAESKeyInKeystore("", 256, KeyStoreOptions.standard())
    }

    @Test(expected = IllegalArgumentException::class)
    fun generateAESKey_invalidKeySize_throws() {
        val alias = createTestAlias("invalid_size")
        keyManager.generateAESKeyInKeystore(alias, 512, KeyStoreOptions.standard())
    }

    @Test(expected = IllegalArgumentException::class)
    fun generateRSAKeyPair_invalidKeySize_throws() {
        val alias = createTestAlias("rsa_invalid")
        keyManager.generateRSAKeyPairInKeystore(alias, 512, KeyStoreOptions.standard())
    }

    // ==================== 密钥属性验证测试 ====================

    @Test
    fun aesKey_hasCorrectProperties() {
        val alias = createTestAlias("aes_props")
        
        val key = keyManager.generateAESKeyInKeystore(alias, 256, KeyStoreOptions.standard())
        
        assertEquals("Algorithm should be AES", "AES", key.algorithm)
        assertEquals("Format should be RAW", "RAW", key.format)
        // AndroidKeyStore 密钥的 encoded 返回 null（不可导出）
        assertNull("Key should not be exportable", key.encoded)
    }

    @Test
    fun rsaKeyPair_hasCorrectProperties() {
        val alias = createTestAlias("rsa_props")
        
        val keyPair = keyManager.generateRSAKeyPairInKeystore(alias, 2048, KeyStoreOptions.standard())
        
        assertEquals("Public key algorithm should be RSA", "RSA", keyPair.public.algorithm)
        assertEquals("Private key algorithm should be RSA", "RSA", keyPair.private.algorithm)
        
        // 公钥可导出，私钥不可导出
        assertNotNull("Public key should be exportable", keyPair.public.encoded)
        assertNull("Private key should not be exportable", keyPair.private.encoded)
    }
}
