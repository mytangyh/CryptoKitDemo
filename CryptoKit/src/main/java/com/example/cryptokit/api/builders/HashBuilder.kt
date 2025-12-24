package com.example.cryptokit.api.builders

import com.example.cryptokit.core.hash.StandardHashEngine
import java.io.InputStream

/**
 * 哈希计算Builder
 */
class HashBuilder(
    private var algorithm: String = "SHA-256"
) {
    private val engine: StandardHashEngine
        get() = StandardHashEngine(algorithm)

    fun algorithm(algorithm: String): HashBuilder = apply { this.algorithm = algorithm }

    fun md5(): HashBuilder = apply { this.algorithm = "MD5" }
    fun sha1(): HashBuilder = apply { this.algorithm = "SHA-1" }
    fun sha256(): HashBuilder = apply { this.algorithm = "SHA-256" }
    fun sha384(): HashBuilder = apply { this.algorithm = "SHA-384" }
    fun sha512(): HashBuilder = apply { this.algorithm = "SHA-512" }

    fun digest(data: ByteArray): ByteArray = engine.hash(data)
    fun digest(data: String): ByteArray = digest(data.toByteArray(Charsets.UTF_8))

    fun digestToHex(data: ByteArray): String = digest(data).joinToString("") { "%02x".format(it) }
    fun digestToHex(data: String): String = digestToHex(data.toByteArray(Charsets.UTF_8))

    fun hmac(data: ByteArray, key: ByteArray): ByteArray = engine.hmac(data, key)
    fun hmac(data: String, key: ByteArray): ByteArray = hmac(data.toByteArray(Charsets.UTF_8), key)

    fun hmacToHex(data: ByteArray, key: ByteArray): String = 
        hmac(data, key).joinToString("") { "%02x".format(it) }
    fun hmacToHex(data: String, key: ByteArray): String = 
        hmacToHex(data.toByteArray(Charsets.UTF_8), key)

    fun digestStream(inputStream: InputStream): ByteArray = engine.hashStream(inputStream)
}
