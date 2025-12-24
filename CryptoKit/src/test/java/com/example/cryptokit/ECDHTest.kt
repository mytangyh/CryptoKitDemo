package com.example.cryptokit

import com.example.cryptokit.core.asymmetric.ECCCipher
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec

/**
 * ECDH 密钥协商单元测试
 */
class ECDHTest {

    @Test
    fun `test ECDH P-256 key agreement`() {
        val cipher = ECCCipher.p256()
        
        // 模拟两方
        val aliceKeyPair = cipher.generateKeyPair()
        val bobKeyPair = cipher.generateKeyPair()
        
        // 双方计算共享密钥
        val aliceSharedSecret = cipher.deriveSharedSecret(aliceKeyPair.private, bobKeyPair.public)
        val bobSharedSecret = cipher.deriveSharedSecret(bobKeyPair.private, aliceKeyPair.public)
        
        // 两方应该得到相同的共享密钥
        assertArrayEquals(aliceSharedSecret, bobSharedSecret)
    }

    @Test
    fun `test ECDH P-384 key agreement`() {
        val cipher = ECCCipher.p384()
        
        val aliceKeyPair = cipher.generateKeyPair()
        val bobKeyPair = cipher.generateKeyPair()
        
        val aliceSharedSecret = cipher.deriveSharedSecret(aliceKeyPair.private, bobKeyPair.public)
        val bobSharedSecret = cipher.deriveSharedSecret(bobKeyPair.private, aliceKeyPair.public)
        
        assertArrayEquals(aliceSharedSecret, bobSharedSecret)
    }

    @Test
    fun `test ECDH shared secret size`() {
        val p256 = ECCCipher.p256()
        val p384 = ECCCipher.p384()
        
        val aliceP256 = p256.generateKeyPair()
        val bobP256 = p256.generateKeyPair()
        val secretP256 = p256.deriveSharedSecret(aliceP256.private, bobP256.public)
        
        val aliceP384 = p384.generateKeyPair()
        val bobP384 = p384.generateKeyPair()
        val secretP384 = p384.deriveSharedSecret(aliceP384.private, bobP384.public)
        
        // P-256: 256 bits = 32 bytes
        assertEquals(32, secretP256.size)
        // P-384: 384 bits = 48 bytes
        assertEquals(48, secretP384.size)
    }

    @Test
    fun `test ECDH different key pairs produce different secrets`() {
        val cipher = ECCCipher.p256()
        
        val alice = cipher.generateKeyPair()
        val bob1 = cipher.generateKeyPair()
        val bob2 = cipher.generateKeyPair()
        
        val secret1 = cipher.deriveSharedSecret(alice.private, bob1.public)
        val secret2 = cipher.deriveSharedSecret(alice.private, bob2.public)
        
        assertFalse(secret1.contentEquals(secret2))
    }

    @Test
    fun `test ECDH is deterministic for same key pairs`() {
        val cipher = ECCCipher.p256()
        
        val alice = cipher.generateKeyPair()
        val bob = cipher.generateKeyPair()
        
        val secret1 = cipher.deriveSharedSecret(alice.private, bob.public)
        val secret2 = cipher.deriveSharedSecret(alice.private, bob.public)
        
        // 相同密钥对应该产生相同的共享密钥
        assertArrayEquals(secret1, secret2)
    }

    @Test(expected = UnsupportedOperationException::class)
    fun `test ECC encrypt throws exception`() {
        val cipher = ECCCipher.p256()
        val keyPair = cipher.generateKeyPair()
        
        // ECC 不支持直接加密
        cipher.encrypt("test".toByteArray(), keyPair.public)
    }

    @Test(expected = UnsupportedOperationException::class)
    fun `test ECC decrypt throws exception`() {
        val cipher = ECCCipher.p256()
        val keyPair = cipher.generateKeyPair()
        
        // ECC 不支持直接解密
        cipher.decrypt("test".toByteArray(), keyPair.private)
    }
}
