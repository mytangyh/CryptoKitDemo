package com.example.cryptokit

import com.example.cryptokit.core.signature.RSASignature
import com.example.cryptokit.core.signature.ECDSASignature
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

/**
 * 数字签名单元测试
 */
class SignatureTest {

    private val testData = "Sign this message".toByteArray()

    // ==================== RSA 签名测试 ====================

    @Test
    fun `test RSA-SHA256 sign and verify`() {
        val signature = RSASignature.sha256()
        val keyPair = generateRSAKeyPair()

        val sig = signature.sign(testData, keyPair.private)
        val isValid = signature.verify(testData, sig, keyPair.public)

        assertTrue(isValid)
    }

    @Test
    fun `test RSA-SHA512 sign and verify`() {
        val signature = RSASignature.sha512()
        val keyPair = generateRSAKeyPair()

        val sig = signature.sign(testData, keyPair.private)
        val isValid = signature.verify(testData, sig, keyPair.public)

        assertTrue(isValid)
    }

    @Test
    fun `test RSA signature verification fails with wrong key`() {
        val signature = RSASignature.sha256()
        val keyPair1 = generateRSAKeyPair()
        val keyPair2 = generateRSAKeyPair()

        val sig = signature.sign(testData, keyPair1.private)
        val isValid = signature.verify(testData, sig, keyPair2.public)

        assertFalse(isValid)
    }

    @Test
    fun `test RSA signature verification fails with modified data`() {
        val signature = RSASignature.sha256()
        val keyPair = generateRSAKeyPair()

        val sig = signature.sign(testData, keyPair.private)
        val modifiedData = "Modified message".toByteArray()
        val isValid = signature.verify(modifiedData, sig, keyPair.public)

        assertFalse(isValid)
    }

    @Test
    fun `test RSA signature verification fails with tampered signature`() {
        val signature = RSASignature.sha256()
        val keyPair = generateRSAKeyPair()

        val sig = signature.sign(testData, keyPair.private)
        // Tamper with signature
        sig[0] = (sig[0].toInt() xor 0xFF).toByte()
        val isValid = signature.verify(testData, sig, keyPair.public)

        assertFalse(isValid)
    }

    // ==================== ECDSA 签名测试 ====================

    @Test
    fun `test ECDSA-SHA256 sign and verify`() {
        val signature = ECDSASignature.sha256()
        val keyPair = generateECKeyPair()

        val sig = signature.sign(testData, keyPair.private)
        val isValid = signature.verify(testData, sig, keyPair.public)

        assertTrue(isValid)
    }

    @Test
    fun `test ECDSA signature is non-deterministic`() {
        val signature = ECDSASignature.sha256()
        val keyPair = generateECKeyPair()

        val sig1 = signature.sign(testData, keyPair.private)
        val sig2 = signature.sign(testData, keyPair.private)

        // ECDSA 使用随机 k 值，每次签名不同
        assertFalse(sig1.contentEquals(sig2))
        
        // 但两个签名都应该验证通过
        assertTrue(signature.verify(testData, sig1, keyPair.public))
        assertTrue(signature.verify(testData, sig2, keyPair.public))
    }

    @Test
    fun `test ECDSA verification fails with wrong key`() {
        val signature = ECDSASignature.sha256()
        val keyPair1 = generateECKeyPair()
        val keyPair2 = generateECKeyPair()

        val sig = signature.sign(testData, keyPair1.private)
        val isValid = signature.verify(testData, sig, keyPair2.public)

        assertFalse(isValid)
    }

    private fun generateRSAKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    private fun generateECKeyPair(): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }
}
