package com.example.cryptokit.core.hash

import com.example.cryptokit.util.SecureRandomUtil
import java.io.InputStream
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * 标准哈希引擎实现
 */
class StandardHashEngine(
    override val algorithmName: String = "SHA-256"
) : HashEngine {

    override val digestLength: Int
        get() = MessageDigest.getInstance(algorithmName).digestLength

    override fun hash(data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(algorithmName)
        return md.digest(data)
    }

    override fun hmac(data: ByteArray, key: ByteArray): ByteArray {
        val hmacAlgorithm = "Hmac${algorithmName.replace("-", "")}"
        val mac = Mac.getInstance(hmacAlgorithm)
        val secretKey = SecretKeySpec(key, hmacAlgorithm)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    override fun hashStream(inputStream: InputStream): ByteArray {
        val md = MessageDigest.getInstance(algorithmName)
        val buffer = ByteArray(8192)
        var bytesRead: Int
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            md.update(buffer, 0, bytesRead)
        }
        return md.digest()
    }

    override fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int
    ): SecretKey {
        val pbkdf2Algorithm = "PBKDF2WithHmac${algorithmName.replace("-", "")}"
        val factory = SecretKeyFactory.getInstance(pbkdf2Algorithm)
        val spec = PBEKeySpec(password, salt, iterations, keyLength)
        return factory.generateSecret(spec)
    }

    companion object {
        fun md5(): StandardHashEngine = StandardHashEngine("MD5")
        fun sha1(): StandardHashEngine = StandardHashEngine("SHA-1")
        fun sha256(): StandardHashEngine = StandardHashEngine("SHA-256")
        fun sha384(): StandardHashEngine = StandardHashEngine("SHA-384")
        fun sha512(): StandardHashEngine = StandardHashEngine("SHA-512")

        fun generateSalt(length: Int = 16): ByteArray = SecureRandomUtil.generateSalt(length)
    }
}
