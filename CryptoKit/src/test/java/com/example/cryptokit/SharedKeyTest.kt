package com.example.cryptokit

import com.example.cryptokit.api.builders.AESBuilder
import com.example.cryptokit.exception.ValidationException
import org.junit.Assert.*
import org.junit.Test

/**
 * 预协商密钥场景单元测试（客户端/服务端通信）
 */
class SharedKeyTest {

    // 模拟预协商的密钥和IV
    private val sharedKey = byteArrayOf(
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ) // 16字节 = 128位

    private val sharedIv = byteArrayOf(
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ) // 16字节

    private val testMessage = "Hello Server! 你好服务端！"

    @Test
    fun `test encrypt and decrypt with shared key using CBC mode`() {
        // 客户端加密
        val ciphertext = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, sharedIv)

        // 服务端解密
        val plaintext = AESBuilder.forSharedKey()
            .decryptWithSharedKeyToString(ciphertext, sharedKey, sharedIv)

        assertEquals(testMessage, plaintext)
    }

    @Test
    fun `test encrypt and decrypt with CTR mode`() {
        // CTR模式也支持预协商密钥
        val ciphertext = AESBuilder()
            .ctr()
            .encryptWithSharedKey(testMessage.toByteArray(), sharedKey, sharedIv)

        val plaintext = AESBuilder()
            .ctr()
            .decryptWithSharedKey(ciphertext, sharedKey, sharedIv)

        assertArrayEquals(testMessage.toByteArray(), plaintext)
    }

    @Test(expected = ValidationException::class)
    fun `test GCM mode throws exception for shared key`() {
        // GCM模式不允许使用固定IV
        AESBuilder()
            .gcm()
            .encryptWithSharedKey(testMessage.toByteArray(), sharedKey, sharedIv)
    }

    @Test
    fun `test same key and iv produce same ciphertext`() {
        val ciphertext1 = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, sharedIv)

        val ciphertext2 = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, sharedIv)

        // 使用相同的key和iv，密文应该相同（CBC模式是确定性的）
        assertArrayEquals(ciphertext1, ciphertext2)
    }

    @Test
    fun `test different iv produces different ciphertext`() {
        val iv1 = sharedIv.clone()
        val iv2 = sharedIv.clone()
        iv2[0] = (iv2[0].toInt() xor 0xFF).toByte()

        val ciphertext1 = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, iv1)

        val ciphertext2 = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, iv2)

        assertFalse(ciphertext1.contentEquals(ciphertext2))
    }

    @Test
    fun `test cross-platform compatibility simulation`() {
        // 模拟客户端和服务端使用相同的预协商密钥
        val clientKey = sharedKey.clone()
        val serverKey = sharedKey.clone()
        val clientIv = sharedIv.clone()
        val serverIv = sharedIv.clone()

        // 客户端发送消息
        val clientMessage = "Request from client"
        val encryptedRequest = AESBuilder.forSharedKey()
            .encryptWithSharedKey(clientMessage, clientKey, clientIv)

        // 服务端接收并解密
        val serverReceivedMessage = AESBuilder.forSharedKey()
            .decryptWithSharedKeyToString(encryptedRequest, serverKey, serverIv)
        assertEquals(clientMessage, serverReceivedMessage)

        // 服务端响应
        val serverResponse = "Response from server"
        val encryptedResponse = AESBuilder.forSharedKey()
            .encryptWithSharedKey(serverResponse, serverKey, serverIv)

        // 客户端接收并解密
        val clientReceivedResponse = AESBuilder.forSharedKey()
            .decryptWithSharedKeyToString(encryptedResponse, clientKey, clientIv)
        assertEquals(serverResponse, clientReceivedResponse)
    }

    @Test
    fun `test 256-bit key with shared key mode`() {
        val key256 = ByteArray(32) { it.toByte() } // 32字节 = 256位

        val ciphertext = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, key256, sharedIv)

        val plaintext = AESBuilder.forSharedKey()
            .decryptWithSharedKeyToString(ciphertext, key256, sharedIv)

        assertEquals(testMessage, plaintext)
    }

    @Test(expected = ValidationException::class)
    fun `test invalid key size throws exception`() {
        val invalidKey = ByteArray(10) { it.toByte() } // 无效大小

        AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, invalidKey, sharedIv)
    }

    @Test(expected = ValidationException::class)
    fun `test invalid iv size throws exception`() {
        val invalidIv = ByteArray(8) { it.toByte() } // 8字节，太短

        AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, invalidIv)
    }

    @Test
    fun `test decryption with wrong key fails`() {
        val wrongKey = ByteArray(16) { 0xFF.toByte() }

        val ciphertext = AESBuilder.forSharedKey()
            .encryptWithSharedKey(testMessage, sharedKey, sharedIv)

        // 使用错误密钥解密应该产生乱码或抛出异常
        try {
            val result = AESBuilder.forSharedKey()
                .decryptWithSharedKeyToString(ciphertext, wrongKey, sharedIv)
            // 如果没抛异常，结果应该不匹配
            assertNotEquals(testMessage, result)
        } catch (e: Exception) {
            // CBC模式使用错误密钥可能抛出填充异常
            assertTrue(e is com.example.cryptokit.exception.DecryptionException)
        }
    }

    @Test
    fun `test large data encryption with shared key`() {
        val largeData = ByteArray(1024 * 100) { (it % 256).toByte() } // 100KB

        val ciphertext = AESBuilder.forSharedKey()
            .encryptWithSharedKey(largeData, sharedKey, sharedIv)

        val plaintext = AESBuilder.forSharedKey()
            .decryptWithSharedKey(ciphertext, sharedKey, sharedIv)

        assertArrayEquals(largeData, plaintext)
    }
}
