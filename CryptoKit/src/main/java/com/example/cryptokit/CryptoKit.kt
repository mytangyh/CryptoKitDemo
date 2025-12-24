package com.example.cryptokit

import java.security.SecureRandom

/**
 * CryptoKit - Android加密套件统一入口
 * 
 * 使用示例:
 * ```kotlin
 * // 零配置AES加密
 * val result = CryptoKit.aes().encrypt("Hello, World!")
 * val plaintext = CryptoKit.aes().decrypt(result)
 * 
 * // RSA加密
 * val keyPair = CryptoKit.rsa().generateKeyPair()
 * val encrypted = CryptoKit.rsa().publicKey(keyPair.public).encrypt("Secret")
 * 
 * // 混合加密
 * val hybridResult = CryptoKit.hybrid().publicKey(publicKey).encrypt(largeData)
 * 
 * // 哈希
 * val hash = CryptoKit.hash().digest("Hello, World!")
 * ```
 */
object CryptoKit {

    // ==================== 对称加密 ====================

    /**
     * AES加密（推荐使用GCM模式）
     * 默认配置：AES-256-GCM，自动生成密钥和IV
     */
    fun aes(): AESBuilder = AESBuilder()

    /**
     * 3DES加密（兼容旧系统）
     */
    fun tripleDes(): TripleDESBuilder = TripleDESBuilder()

    // ==================== 非对称加密 ====================

    /**
     * RSA加密/签名
     * 默认配置：RSA-2048，OAEP填充
     */
    fun rsa(): RSABuilder = RSABuilder()

    /**
     * ECC加密/签名
     * 默认配置：P-256曲线
     */
    fun ecc(): ECCBuilder = ECCBuilder()

    // ==================== 组合加密 ====================

    /**
     * 混合加密（RSA+AES）
     * 适用于加密大量数据
     */
    fun hybrid(): HybridBuilder = HybridBuilder()

    // ==================== 哈希 ====================

    /**
     * 哈希计算
     * 默认配置：SHA-256
     */
    fun hash(algorithm: HashAlgorithm = HashAlgorithm.SHA256): HashEngine = HashEngine(algorithm)

    // ==================== 编码 ====================

    /**
     * 编码工具
     */
    val encode: EncodingKit = EncodingKit

    // ==================== 密钥管理 ====================

    /**
     * 密钥管理器（Android Keystore）
     */
    val keyManager: KeyManager = KeyManager

    // ==================== 快捷方法 ====================

    /**
     * 快速SHA-256哈希
     */
    fun sha256(data: String): String = hash(HashAlgorithm.SHA256).digestToHex(data)

    /**
     * 快速SHA-256哈希（字节数组）
     */
    fun sha256(data: ByteArray): ByteArray = hash(HashAlgorithm.SHA256).digest(data)

    /**
     * 快速SHA-512哈希
     */
    fun sha512(data: String): String = hash(HashAlgorithm.SHA512).digestToHex(data)

    /**
     * 快速SHA-512哈希（字节数组）
     */
    fun sha512(data: ByteArray): ByteArray = hash(HashAlgorithm.SHA512).digest(data)

    /**
     * 快速MD5哈希（仅用于非安全场景）
     */
    fun md5(data: String): String = hash(HashAlgorithm.MD5).digestToHex(data)

    /**
     * 快速MD5哈希（字节数组）
     */
    fun md5(data: ByteArray): ByteArray = hash(HashAlgorithm.MD5).digest(data)

    /**
     * 生成安全随机数
     */
    fun secureRandom(length: Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    /**
     * 生成随机UUID字符串
     */
    fun randomUUID(): String = java.util.UUID.randomUUID().toString()

    /**
     * 计算HMAC
     */
    fun hmac(
        data: String,
        key: ByteArray,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ): ByteArray = HashEngine.hmac(data, key, algorithm)

    /**
     * 计算HMAC（返回十六进制字符串）
     */
    fun hmacToHex(
        data: String,
        key: ByteArray,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ): String = HashEngine.hmac(data, key, algorithm).toHex()

    /**
     * 密钥派生（PBKDF2）
     */
    fun deriveKey(
        password: String,
        salt: ByteArray,
        iterations: Int = 10000,
        keyLength: Int = 256,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256
    ): ByteArray = HashEngine.deriveKey(password.toCharArray(), salt, iterations, keyLength, algorithm)
}
