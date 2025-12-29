package com.example.cryptokit

import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.core.signature.RSASignature
import com.example.cryptokit.core.signature.ECDSASignature
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

/**
 * 性能基准测试套件
 * 
 * 金融级测试要求：
 * - 各算法加解密性能对比
 * - 不同密钥大小性能对比
 * - 不同数据大小性能对比
 * - 吞吐量测试
 * - 延迟测试
 */
class PerformanceBenchmarkTest {

    private val warmupIterations = 100
    private val benchmarkIterations = 1000
    
    // 测试数据大小
    private val smallData = ByteArray(100) { (it % 256).toByte() }           // 100 B
    private val mediumData = ByteArray(10 * 1024) { (it % 256).toByte() }    // 10 KB
    private val largeData = ByteArray(1024 * 1024) { (it % 256).toByte() }   // 1 MB

    @Before
    fun setUp() {
        // JVM 预热
        System.gc()
    }

    // ==================== AES 性能测试 ====================

    @Test
    fun `AES-GCM performance benchmark`() {
        val cipher = AESCipher.gcm()
        val key = generateAESKey(256)
        
        println("\n=== AES-256-GCM Performance ===")
        
        // 小数据
        benchmarkAES(cipher, key, smallData, "100B")
        
        // 中等数据
        benchmarkAES(cipher, key, mediumData, "10KB")
        
        // 大数据
        benchmarkAES(cipher, key, largeData, "1MB")
    }

    @Test
    fun `AES-CBC performance benchmark`() {
        val cipher = AESCipher.cbc()
        val key = generateAESKey(256)
        
        println("\n=== AES-256-CBC Performance ===")
        
        benchmarkAES(cipher, key, smallData, "100B")
        benchmarkAES(cipher, key, mediumData, "10KB")
        benchmarkAES(cipher, key, largeData, "1MB")
    }

    @Test
    fun `AES-CTR performance benchmark`() {
        val cipher = AESCipher.ctr()
        val key = generateAESKey(256)
        
        println("\n=== AES-256-CTR Performance ===")
        
        benchmarkAES(cipher, key, smallData, "100B")
        benchmarkAES(cipher, key, mediumData, "10KB")
        benchmarkAES(cipher, key, largeData, "1MB")
    }

    @Test
    fun `AES key size performance comparison`() {
        val cipher = AESCipher.gcm()
        val testData = mediumData
        
        println("\n=== AES Key Size Performance Comparison (10KB data) ===")
        
        listOf(128, 192, 256).forEach { keySize ->
            val key = generateAESKey(keySize)
            
            // 预热
            repeat(warmupIterations) {
                val iv = cipher.generateIV()
                val ct = cipher.encrypt(testData, key, iv)
                cipher.decrypt(ct, key, iv)
            }
            
            // 基准测试
            val startTime = System.nanoTime()
            repeat(benchmarkIterations) {
                val iv = cipher.generateIV()
                val ct = cipher.encrypt(testData, key, iv)
                cipher.decrypt(ct, key, iv)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            
            val opsPerSec = (benchmarkIterations * 1000.0 / duration).toInt()
            println("AES-$keySize-GCM: ${duration.format(2)}ms total, ${(duration/benchmarkIterations).format(3)}ms/op, $opsPerSec ops/sec")
        }
    }

    private fun benchmarkAES(cipher: AESCipher, key: javax.crypto.SecretKey, data: ByteArray, label: String) {
        // 预热
        repeat(warmupIterations) {
            val iv = cipher.generateIV()
            val ct = cipher.encrypt(data, key, iv)
            cipher.decrypt(ct, key, iv)
        }
        
        // 加密基准
        var encryptTotal = 0L
        repeat(benchmarkIterations) {
            val iv = cipher.generateIV()
            val start = System.nanoTime()
            cipher.encrypt(data, key, iv)
            encryptTotal += System.nanoTime() - start
        }
        
        // 解密基准
        val iv = cipher.generateIV()
        val ciphertext = cipher.encrypt(data, key, iv)
        var decryptTotal = 0L
        repeat(benchmarkIterations) {
            val start = System.nanoTime()
            cipher.decrypt(ciphertext, key, iv)
            decryptTotal += System.nanoTime() - start
        }
        
        val encryptMs = encryptTotal / 1_000_000.0
        val decryptMs = decryptTotal / 1_000_000.0
        val throughputMBps = (data.size.toLong() * benchmarkIterations / (encryptMs + decryptMs) * 1000 / 1024 / 1024).format(2)
        
        println("$label: Encrypt ${(encryptMs/benchmarkIterations).format(3)}ms, Decrypt ${(decryptMs/benchmarkIterations).format(3)}ms, Throughput ${throughputMBps} MB/s")
    }

    // ==================== RSA 性能测试 ====================

    @Test
    fun `RSA performance benchmark by key size`() {
        val rsaIterations = 100 // RSA 较慢
        val testData = smallData.copyOf(100)
        
        println("\n=== RSA Performance by Key Size ===")
        
        listOf(1024, 2048, 4096).forEach { keySize ->
            val cipher = RSACipher.oaepSha256()
            val keyPair = cipher.generateKeyPair(keySize)
            
            // 计算最大明文长度
            val maxPlaintext = when(keySize) {
                1024 -> 62
                2048 -> 190
                4096 -> 446
                else -> 100
            }
            val actualData = testData.copyOf(minOf(testData.size, maxPlaintext))
            
            // 预热
            repeat(10) {
                val ct = cipher.encrypt(actualData, keyPair.public)
                cipher.decrypt(ct, keyPair.private)
            }
            
            // 加密基准
            val encryptStart = System.nanoTime()
            repeat(rsaIterations) {
                cipher.encrypt(actualData, keyPair.public)
            }
            val encryptMs = (System.nanoTime() - encryptStart) / 1_000_000.0
            
            // 解密基准
            val ciphertext = cipher.encrypt(actualData, keyPair.public)
            val decryptStart = System.nanoTime()
            repeat(rsaIterations) {
                cipher.decrypt(ciphertext, keyPair.private)
            }
            val decryptMs = (System.nanoTime() - decryptStart) / 1_000_000.0
            
            println("RSA-$keySize: Encrypt ${(encryptMs/rsaIterations).format(3)}ms, Decrypt ${(decryptMs/rsaIterations).format(3)}ms")
        }
    }

    @Test
    fun `RSA padding scheme performance comparison`() {
        val rsaIterations = 100
        val testData = smallData.copyOf(100)
        
        println("\n=== RSA Padding Performance Comparison (2048-bit) ===")
        
        val keyPair = RSACipher.oaepSha256().generateKeyPair(2048)
        
        mapOf(
            "OAEP-SHA256" to RSACipher.oaepSha256(),
            "OAEP-SHA1" to RSACipher.oaepSha1(),
            "PKCS1" to RSACipher.pkcs1()
        ).forEach { (name, cipher) ->
            // 调整数据大小
            val maxLen = when(name) {
                "OAEP-SHA256" -> 190
                "OAEP-SHA1" -> 214
                "PKCS1" -> 245
                else -> 100
            }
            val data = testData.copyOf(minOf(testData.size, maxLen))
            
            // 预热
            repeat(10) {
                val ct = cipher.encrypt(data, keyPair.public)
                cipher.decrypt(ct, keyPair.private)
            }
            
            val startTime = System.nanoTime()
            repeat(rsaIterations) {
                val ct = cipher.encrypt(data, keyPair.public)
                cipher.decrypt(ct, keyPair.private)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            
            println("$name: ${(duration/rsaIterations).format(3)}ms/op")
        }
    }

    // ==================== 签名性能测试 ====================

    @Test
    fun `Signature algorithm performance comparison`() {
        val iterations = 100
        val testData = mediumData
        
        println("\n=== Signature Performance Comparison ===")
        
        // RSA 签名
        val rsaKeyPair = generateRSAKeyPair(2048)
        listOf(
            "SHA256withRSA" to RSASignature.sha256(),
            "SHA512withRSA" to RSASignature.sha512()
        ).forEach { (name, signature) ->
            // 预热
            repeat(10) {
                val sig = signature.sign(testData, rsaKeyPair.private)
                signature.verify(testData, sig, rsaKeyPair.public)
            }
            
            // 签名基准
            val signStart = System.nanoTime()
            repeat(iterations) {
                signature.sign(testData, rsaKeyPair.private)
            }
            val signMs = (System.nanoTime() - signStart) / 1_000_000.0
            
            // 验签基准
            val sig = signature.sign(testData, rsaKeyPair.private)
            val verifyStart = System.nanoTime()
            repeat(iterations) {
                signature.verify(testData, sig, rsaKeyPair.public)
            }
            val verifyMs = (System.nanoTime() - verifyStart) / 1_000_000.0
            
            println("$name: Sign ${(signMs/iterations).format(3)}ms, Verify ${(verifyMs/iterations).format(3)}ms")
        }
        
        // ECDSA 签名
        val ecKeyPair = generateECKeyPair()
        listOf(
            "SHA256withECDSA" to ECDSASignature.sha256()
        ).forEach { (name, signature) ->
            // 预热
            repeat(10) {
                val sig = signature.sign(testData, ecKeyPair.private)
                signature.verify(testData, sig, ecKeyPair.public)
            }
            
            val signStart = System.nanoTime()
            repeat(iterations) {
                signature.sign(testData, ecKeyPair.private)
            }
            val signMs = (System.nanoTime() - signStart) / 1_000_000.0
            
            val sig = signature.sign(testData, ecKeyPair.private)
            val verifyStart = System.nanoTime()
            repeat(iterations) {
                signature.verify(testData, sig, ecKeyPair.public)
            }
            val verifyMs = (System.nanoTime() - verifyStart) / 1_000_000.0
            
            println("$name: Sign ${(signMs/iterations).format(3)}ms, Verify ${(verifyMs/iterations).format(3)}ms")
        }
    }

    // ==================== 哈希性能测试 ====================

    @Test
    fun `Hash algorithm performance comparison`() {
        println("\n=== Hash Algorithm Performance (1MB data) ===")
        
        listOf("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512").forEach { algorithm ->
            val hashEngine = StandardHashEngine(algorithm)
            
            // 预热
            repeat(warmupIterations) {
                hashEngine.hash(largeData)
            }
            
            val startTime = System.nanoTime()
            repeat(benchmarkIterations) {
                hashEngine.hash(largeData)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            
            val throughputMBps = (largeData.size.toLong() * benchmarkIterations / duration * 1000 / 1024 / 1024).format(2)
            println("$algorithm: ${(duration/benchmarkIterations).format(3)}ms/hash, Throughput: $throughputMBps MB/s")
        }
    }

    @Test
    fun `HMAC performance benchmark`() {
        val hashEngine = StandardHashEngine.sha256()
        val hmacKey = ByteArray(32) { it.toByte() }
        
        println("\n=== HMAC-SHA256 Performance ===")
        
        listOf(
            "100B" to smallData,
            "10KB" to mediumData,
            "1MB" to largeData
        ).forEach { (label, data) ->
            // 预热
            repeat(warmupIterations) {
                hashEngine.hmac(data, hmacKey)
            }
            
            val startTime = System.nanoTime()
            repeat(benchmarkIterations) {
                hashEngine.hmac(data, hmacKey)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            
            val throughputMBps = (data.size.toLong() * benchmarkIterations / duration * 1000 / 1024 / 1024).format(2)
            println("$label: ${(duration/benchmarkIterations).format(3)}ms/hmac, Throughput: $throughputMBps MB/s")
        }
    }

    // ==================== PBKDF2 性能测试 ====================

    @Test
    fun `PBKDF2 iteration count performance`() {
        val hashEngine = StandardHashEngine.sha256()
        val password = "MySecurePassword123!".toCharArray()
        val salt = ByteArray(16) { it.toByte() }
        
        println("\n=== PBKDF2-SHA256 Performance by Iteration Count ===")
        
        listOf(1000, 10000, 50000, 100000, 200000).forEach { iterations ->
            val startTime = System.nanoTime()
            repeat(10) {
                hashEngine.deriveKey(password, salt, iterations, 256)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0 / 10
            
            println("$iterations iterations: ${duration.format(2)}ms/derivation")
        }
    }

    // ==================== 密钥生成性能测试 ====================

    @Test
    fun `Key generation performance`() {
        val iterations = 100
        
        println("\n=== Key Generation Performance ===")
        
        // AES 密钥生成
        listOf(128, 192, 256).forEach { keySize ->
            val startTime = System.nanoTime()
            repeat(iterations) {
                generateAESKey(keySize)
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            println("AES-$keySize key generation: ${(duration/iterations).format(3)}ms/key")
        }
        
        // RSA 密钥对生成
        listOf(1024, 2048, 4096).forEach { keySize ->
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            
            val startTime = System.nanoTime()
            val genIterations = if (keySize >= 4096) 5 else 10
            repeat(genIterations) {
                keyPairGenerator.initialize(keySize, SecureRandom())
                keyPairGenerator.generateKeyPair()
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            println("RSA-$keySize keypair generation: ${(duration/genIterations).format(2)}ms/keypair")
        }
        
        // EC 密钥对生成
        listOf("secp256r1", "secp384r1").forEach { curve ->
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            
            val startTime = System.nanoTime()
            repeat(iterations) {
                keyPairGenerator.initialize(ECGenParameterSpec(curve), SecureRandom())
                keyPairGenerator.generateKeyPair()
            }
            val duration = (System.nanoTime() - startTime) / 1_000_000.0
            println("EC $curve keypair generation: ${(duration/iterations).format(3)}ms/keypair")
        }
    }

    // ==================== 综合性能报告 ====================

    @Test
    fun `Generate comprehensive performance report`() {
        println("\n" + "=".repeat(60))
        println("       CRYPTOKIT PERFORMANCE BENCHMARK REPORT")
        println("=".repeat(60))
        
        // 运行所有基准测试
        `AES-GCM performance benchmark`()
        `RSA performance benchmark by key size`()
        `Signature algorithm performance comparison`()
        `Hash algorithm performance comparison`()
        
        println("\n" + "=".repeat(60))
        println("                    END OF REPORT")
        println("=".repeat(60))
    }

    // ==================== 辅助方法 ====================

    private fun generateAESKey(keySize: Int): javax.crypto.SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(keySize, SecureRandom())
        return keyGenerator.generateKey()
    }

    private fun generateRSAKeyPair(keySize: Int): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    private fun generateECKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    private fun Double.format(decimals: Int): String = "%.${decimals}f".format(this)
}
