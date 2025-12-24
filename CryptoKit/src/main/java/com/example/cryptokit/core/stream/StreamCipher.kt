package com.example.cryptokit.core.stream

import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.DecryptionException
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec

/**
 * 流式加密处理器
 * 
 * 金融级特性：
 * - 支持大文件加密，避免OOM
 * - 分块处理，内存占用可控
 * - 自动资源管理
 * 
 * 使用示例：
 * ```kotlin
 * StreamCipher.encryptStream(
 *     inputStream = fileInputStream,
 *     outputStream = encryptedOutputStream,
 *     key = aesKey,
 *     iv = iv
 * )
 * ```
 */
object StreamCipher {
    
    private const val DEFAULT_BUFFER_SIZE = 8192
    
    /**
     * 流式AES加密
     * 
     * @param inputStream 明文输入流
     * @param outputStream 密文输出流
     * @param key AES密钥
     * @param iv 初始化向量
     * @param mode 加密模式 (GCM/CBC/CTR)
     * @param bufferSize 缓冲区大小
     * @return 处理的字节数
     */
    fun encryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: SecretKey,
        iv: ByteArray,
        mode: String = "CBC",
        bufferSize: Int = DEFAULT_BUFFER_SIZE
    ): Long {
        // 注意：GCM模式不适合流式处理，因为需要完整数据计算认证标签
        if (mode == "GCM") {
            throw EncryptionException(
                "GCM mode is not suitable for streaming. Use CBC or CTR mode, " +
                "or encrypt the entire data at once for GCM authentication."
            )
        }
        
        try {
            val cipher = createCipher(Cipher.ENCRYPT_MODE, key, iv, mode)
            return processStream(inputStream, outputStream, cipher, bufferSize)
        } catch (e: EncryptionException) {
            throw e
        } catch (e: Exception) {
            throw EncryptionException("Stream encryption failed: ${e.message}", e)
        }
    }
    
    /**
     * 流式AES解密
     * 
     * @param inputStream 密文输入流
     * @param outputStream 明文输出流
     * @param key AES密钥
     * @param iv 初始化向量
     * @param mode 加密模式 (CBC/CTR)
     * @param bufferSize 缓冲区大小
     * @return 处理的字节数
     */
    fun decryptStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        key: SecretKey,
        iv: ByteArray,
        mode: String = "CBC",
        bufferSize: Int = DEFAULT_BUFFER_SIZE
    ): Long {
        if (mode == "GCM") {
            throw DecryptionException(
                "GCM mode is not suitable for streaming. Use CBC or CTR mode."
            )
        }
        
        try {
            val cipher = createCipher(Cipher.DECRYPT_MODE, key, iv, mode)
            return processStream(inputStream, outputStream, cipher, bufferSize)
        } catch (e: DecryptionException) {
            throw e
        } catch (e: Exception) {
            throw DecryptionException("Stream decryption failed: ${e.message}", e)
        }
    }
    
    /**
     * 使用CipherOutputStream加密
     */
    fun createEncryptOutputStream(
        outputStream: OutputStream,
        key: SecretKey,
        iv: ByteArray,
        mode: String = "CBC"
    ): CipherOutputStream {
        val cipher = createCipher(Cipher.ENCRYPT_MODE, key, iv, mode)
        return CipherOutputStream(outputStream, cipher)
    }
    
    /**
     * 使用CipherInputStream解密
     */
    fun createDecryptInputStream(
        inputStream: InputStream,
        key: SecretKey,
        iv: ByteArray,
        mode: String = "CBC"
    ): CipherInputStream {
        val cipher = createCipher(Cipher.DECRYPT_MODE, key, iv, mode)
        return CipherInputStream(inputStream, cipher)
    }
    
    private fun createCipher(
        opMode: Int,
        key: SecretKey,
        iv: ByteArray,
        mode: String
    ): Cipher {
        val transformation = when (mode.uppercase()) {
            "CBC" -> "AES/CBC/PKCS5Padding"
            "CTR" -> "AES/CTR/NoPadding"
            else -> throw IllegalArgumentException("Unsupported stream mode: $mode")
        }
        
        val cipher = Cipher.getInstance(transformation)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(opMode, key, ivSpec)
        return cipher
    }
    
    private fun processStream(
        inputStream: InputStream,
        outputStream: OutputStream,
        cipher: Cipher,
        bufferSize: Int
    ): Long {
        val buffer = ByteArray(bufferSize)
        var totalBytes = 0L
        var bytesRead: Int
        
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            val output = cipher.update(buffer, 0, bytesRead)
            if (output != null) {
                outputStream.write(output)
            }
            totalBytes += bytesRead
        }
        
        // 处理最后的块
        val finalOutput = cipher.doFinal()
        if (finalOutput != null && finalOutput.isNotEmpty()) {
            outputStream.write(finalOutput)
        }
        
        outputStream.flush()
        return totalBytes
    }
    
    /**
     * 计算加密后预估大小
     */
    fun estimateEncryptedSize(plainSize: Long, mode: String): Long {
        return when (mode.uppercase()) {
            "CBC" -> {
                // CBC需要填充到块大小的倍数
                val blockSize = 16
                ((plainSize / blockSize) + 1) * blockSize
            }
            "CTR" -> plainSize // CTR模式不改变大小
            else -> plainSize
        }
    }
}
