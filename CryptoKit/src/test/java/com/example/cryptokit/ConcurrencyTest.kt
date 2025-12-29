package com.example.cryptokit

import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.core.signature.RSASignature
import com.example.cryptokit.core.signature.ECDSASignature
import com.example.cryptokit.interceptor.InterceptorChain
import org.junit.Assert.*
import org.junit.Before
import org.junit.After
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.KeyGenerator

/**
 * 并发测试套件
 * 
 * 金融级测试要求：
 * - 多线程同时加解密
 * - 多线程共享密钥操作
 * - 拦截器链并发安全
 * - 高并发场景下的正确性
 * - 竞态条件检测
 */
class ConcurrencyTest {

    private val threadCount = 10
    private val iterationsPerThread = 100
    private lateinit var executor: ExecutorService

    @Before
    fun setUp() {
        executor = Executors.newFixedThreadPool(threadCount)
        InterceptorChain.reset()
    }

    @After
    fun tearDown() {
        executor.shutdown()
        executor.awaitTermination(60, TimeUnit.SECONDS)
        InterceptorChain.reset()
    }

    // ==================== AES 并发测试 ====================

    @Test
    fun `AES-GCM concurrent encryption with shared key`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        val testData = "Concurrent test data 并发测试数据".toByteArray()
        
        val errorCount = AtomicInteger(0)
        val successCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) { threadId ->
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        val iv = cipher.generateIV() // 每次新 IV
                        val ciphertext = cipher.encrypt(testData, key, iv)
                        val decrypted = cipher.decrypt(ciphertext, key, iv)
                        
                        if (testData.contentEquals(decrypted)) {
                            successCount.incrementAndGet()
                        } else {
                            errorCount.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(60, TimeUnit.SECONDS)
        
        assertEquals("Expected zero errors", 0, errorCount.get())
        assertEquals("Expected all operations to succeed", 
            threadCount * iterationsPerThread, successCount.get())
    }

    @Test
    fun `AES-CBC concurrent encryption different keys`() {
        val cipher = AESCipher.cbc()
        val testData = "CBC concurrent test 并发CBC测试".toByteArray()
        
        val results = ConcurrentHashMap<Int, Boolean>()
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) { threadId ->
            executor.submit {
                try {
                    val key = generateAESKey(256) // 每个线程独立密钥
                    repeat(iterationsPerThread) { iteration ->
                        val iv = cipher.generateIV()
                        val ciphertext = cipher.encrypt(testData, key, iv)
                        val decrypted = cipher.decrypt(ciphertext, key, iv)
                        
                        val operationId = threadId * iterationsPerThread + iteration
                        results[operationId] = testData.contentEquals(decrypted)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(60, TimeUnit.SECONDS)
        
        val failures = results.values.count { !it }
        assertEquals("Expected no failures", 0, failures)
        assertEquals("Expected all operations completed", 
            threadCount * iterationsPerThread, results.size)
    }

    // ==================== RSA 并发测试 ====================

    @Test
    fun `RSA concurrent encryption with shared key pair`() {
        val rsaCipher = RSACipher.oaepSha256()
        val keyPair = rsaCipher.generateKeyPair(2048)
        val testData = "RSA concurrent test".toByteArray()
        
        val errorCount = AtomicInteger(0)
        val successCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread / 10) { // RSA 较慢，减少迭代
                        val ciphertext = rsaCipher.encrypt(testData, keyPair.public)
                        val decrypted = rsaCipher.decrypt(ciphertext, keyPair.private)
                        
                        if (testData.contentEquals(decrypted)) {
                            successCount.incrementAndGet()
                        } else {
                            errorCount.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(120, TimeUnit.SECONDS)
        
        assertEquals("Expected zero errors", 0, errorCount.get())
    }

    @Test
    fun `RSA signature concurrent sign and verify`() {
        val signature = RSASignature.sha256()
        val keyPair = generateRSAKeyPair()
        val testData = "Sign me concurrently".toByteArray()
        
        val errorCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread / 10) {
                        val sig = signature.sign(testData, keyPair.private)
                        val isValid = signature.verify(testData, sig, keyPair.public)
                        
                        if (!isValid) {
                            errorCount.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(120, TimeUnit.SECONDS)
        assertEquals("Expected all signatures to verify", 0, errorCount.get())
    }

    // ==================== 哈希并发测试 ====================

    @Test
    fun `Hash concurrent operations produce consistent results`() {
        val hashEngine = StandardHashEngine.sha256()
        val testData = "Hash concurrent test data".toByteArray()
        val expectedHash = hashEngine.hash(testData)
        
        val errorCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        val hash = hashEngine.hash(testData)
                        if (!expectedHash.contentEquals(hash)) {
                            errorCount.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        assertEquals("Hash should be deterministic", 0, errorCount.get())
    }

    @Test
    fun `HMAC concurrent operations with shared key`() {
        val hashEngine = StandardHashEngine.sha256()
        val hmacKey = ByteArray(32) { it.toByte() }
        val testData = "HMAC concurrent test".toByteArray()
        val expectedHmac = hashEngine.hmac(testData, hmacKey)
        
        val errorCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        val hmac = hashEngine.hmac(testData, hmacKey)
                        if (!expectedHmac.contentEquals(hmac)) {
                            errorCount.incrementAndGet()
                        }
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        assertEquals("HMAC should be deterministic", 0, errorCount.get())
    }

    // ==================== 拦截器并发测试 ====================

    @Test
    fun `InterceptorChain concurrent add and remove`() {
        val errorCount = AtomicInteger(0)
        val operationCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount * 2)

        // 一半线程添加拦截器
        repeat(threadCount) { id ->
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        InterceptorChain.addInterceptor(TestInterceptor("test-$id-$it"))
                        operationCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        // 另一半线程使用拦截器
        repeat(threadCount) {
            executor.submit {
                try {
                    InterceptorChain.enable()
                    repeat(iterationsPerThread) {
                        val data = ByteArray(10) { it.toByte() }
                        InterceptorChain.beforeEncrypt(data, "AES")
                        InterceptorChain.afterEncrypt(data, "AES")
                        operationCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                    e.printStackTrace()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(60, TimeUnit.SECONDS)
        assertEquals("No errors expected in concurrent interceptor operations", 0, errorCount.get())
        
        // 清理
        InterceptorChain.reset()
    }

    // ==================== 混合并发测试 ====================

    @Test
    fun `Mixed operations concurrent stress test`() {
        val aesGcm = AESCipher.gcm()
        val aesCbc = AESCipher.cbc()
        val rsa = RSACipher.oaepSha256()
        val hash = StandardHashEngine.sha256()
        
        val aesKey = generateAESKey(256)
        val rsaKeyPair = rsa.generateKeyPair(2048)
        val testData = "Mixed concurrent stress test data".toByteArray()
        
        val errorCount = AtomicInteger(0)
        val successCount = AtomicInteger(0)
        val latch = CountDownLatch(threadCount * 4)

        // AES-GCM 线程
        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        val iv = aesGcm.generateIV()
                        val encrypted = aesGcm.encrypt(testData, aesKey, iv)
                        val decrypted = aesGcm.decrypt(encrypted, aesKey, iv)
                        if (testData.contentEquals(decrypted)) successCount.incrementAndGet()
                        else errorCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        // AES-CBC 线程
        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread) {
                        val iv = aesCbc.generateIV()
                        val encrypted = aesCbc.encrypt(testData, aesKey, iv)
                        val decrypted = aesCbc.decrypt(encrypted, aesKey, iv)
                        if (testData.contentEquals(decrypted)) successCount.incrementAndGet()
                        else errorCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        // Hash 线程
        repeat(threadCount) {
            executor.submit {
                try {
                    val expectedHash = hash.hash(testData)
                    repeat(iterationsPerThread) {
                        val computed = hash.hash(testData)
                        if (expectedHash.contentEquals(computed)) successCount.incrementAndGet()
                        else errorCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        // RSA 线程 (较少迭代)
        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(iterationsPerThread / 20) {
                        val encrypted = rsa.encrypt(testData, rsaKeyPair.public)
                        val decrypted = rsa.decrypt(encrypted, rsaKeyPair.private)
                        if (testData.contentEquals(decrypted)) successCount.incrementAndGet()
                        else errorCount.incrementAndGet()
                    }
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(180, TimeUnit.SECONDS)
        
        assertEquals("Expected zero errors in mixed concurrent test", 0, errorCount.get())
        println("Total successful operations: ${successCount.get()}")
    }

    // ==================== 竞态条件检测 ====================

    @Test
    fun `No race condition in IV generation`() {
        val cipher = AESCipher.gcm()
        val ivs = ConcurrentHashMap.newKeySet<String>()
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(1000) {
                        val iv = cipher.generateIV()
                        ivs.add(iv.toHexString())
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        
        // 所有 IV 应该唯一
        assertEquals("All IVs should be unique", threadCount * 1000, ivs.size)
    }

    @Test
    fun `No race condition in key generation`() {
        val keys = ConcurrentHashMap.newKeySet<String>()
        val latch = CountDownLatch(threadCount)

        repeat(threadCount) {
            executor.submit {
                try {
                    repeat(100) {
                        val key = generateAESKey(256)
                        keys.add(key.encoded.toHexString())
                    }
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        
        // 所有密钥应该唯一
        assertEquals("All keys should be unique", threadCount * 100, keys.size)
    }

    // ==================== 辅助方法 ====================

    private fun generateAESKey(keySize: Int): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    private fun generateRSAKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    /**
     * 测试用拦截器
     */
    private class TestInterceptor(override val name: String) : 
        com.example.cryptokit.interceptor.CryptoInterceptor {
        
        override val priority: Int = 100
        
        override fun beforeEncrypt(plaintext: ByteArray, algorithm: String): ByteArray = plaintext
        override fun afterEncrypt(ciphertext: ByteArray, algorithm: String): ByteArray = ciphertext
        override fun beforeDecrypt(ciphertext: ByteArray, algorithm: String): ByteArray = ciphertext
        override fun afterDecrypt(plaintext: ByteArray, algorithm: String): ByteArray = plaintext
    }
}
