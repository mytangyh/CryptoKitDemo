package com.example.cryptokit

/**
 * 对称加密算法枚举
 */
enum class SymmetricAlgorithm(
    val algorithmName: String,
    val keySizes: IntArray,
    val blockSize: Int,
    val isRecommended: Boolean = false
) {
    // AES系列（推荐）
    AES_128("AES", intArrayOf(128), 16),
    AES_192("AES", intArrayOf(192), 16),
    AES_256("AES", intArrayOf(256), 16, true),

    // ChaCha20（推荐，移动端性能优秀）
    CHACHA20("ChaCha20", intArrayOf(256), 0, true),
    CHACHA20_POLY1305("ChaCha20-Poly1305", intArrayOf(256), 0, true),

    // 传统算法（兼容性）
    DES("DES", intArrayOf(56), 8),
    TRIPLE_DES("DESede", intArrayOf(112, 168), 8);

    val defaultKeySize: Int get() = keySizes.last()
}

/**
 * 非对称加密算法枚举
 */
enum class AsymmetricAlgorithm(
    val algorithmName: String,
    val keySizes: IntArray,
    val isRecommended: Boolean = false
) {
    // RSA系列
    RSA_1024("RSA", intArrayOf(1024)),
    RSA_2048("RSA", intArrayOf(2048), true),
    RSA_4096("RSA", intArrayOf(4096)),

    // ECDSA系列（推荐）
    ECDSA_P256("EC", intArrayOf(256), true),
    ECDSA_P384("EC", intArrayOf(384)),
    ECDSA_P521("EC", intArrayOf(521)),

    // ECDH密钥协商
    ECDH_P256("EC", intArrayOf(256)),
    ECDH_P384("EC", intArrayOf(384)),

    // DSA（传统）
    DSA_1024("DSA", intArrayOf(1024)),
    DSA_2048("DSA", intArrayOf(2048));

    val defaultKeySize: Int get() = keySizes.last()
}

/**
 * 加密模式枚举
 */
enum class CipherMode(val modeName: String) {
    ECB("ECB"),     // 电子密码本（不推荐）
    CBC("CBC"),     // 密码块链接
    CTR("CTR"),     // 计数器模式
    GCM("GCM"),     // Galois/Counter Mode（认证加密，推荐）
    CFB("CFB"),     // 密文反馈
    OFB("OFB")      // 输出反馈
}

/**
 * 填充方案枚举
 */
enum class PaddingScheme(val paddingName: String) {
    NO_PADDING("NoPadding"),
    PKCS5_PADDING("PKCS5Padding"),
    PKCS7_PADDING("PKCS7Padding"),
    ISO10126_PADDING("ISO10126Padding")
}

/**
 * RSA填充方案枚举
 */
enum class RSAPadding(val paddingName: String) {
    PKCS1("PKCS1Padding"),
    OAEP_SHA1("OAEPWithSHA-1AndMGF1Padding"),
    OAEP_SHA256("OAEPWithSHA-256AndMGF1Padding")
}

/**
 * 签名算法枚举
 */
enum class SignatureAlgorithm(
    val algorithmName: String,
    val isRecommended: Boolean = false
) {
    // RSA签名
    SHA1_WITH_RSA("SHA1withRSA"),
    SHA256_WITH_RSA("SHA256withRSA", true),
    SHA384_WITH_RSA("SHA384withRSA"),
    SHA512_WITH_RSA("SHA512withRSA"),

    // ECDSA签名
    SHA256_WITH_ECDSA("SHA256withECDSA", true),
    SHA384_WITH_ECDSA("SHA384withECDSA"),
    SHA512_WITH_ECDSA("SHA512withECDSA"),

    // DSA签名
    SHA256_WITH_DSA("SHA256withDSA")
}

/**
 * 哈希算法枚举
 */
enum class HashAlgorithm(
    val algorithmName: String,
    val digestLength: Int,
    val isRecommended: Boolean = false,
    val isSecure: Boolean = true
) {
    // MD系列（不安全，仅用于非安全场景）
    MD5("MD5", 16, false, false),

    // SHA-1（不推荐用于签名）
    SHA1("SHA-1", 20, false, false),

    // SHA-2系列（推荐）
    SHA256("SHA-256", 32, true),
    SHA384("SHA-384", 48),
    SHA512("SHA-512", 64, true)
}

/**
 * 编码类型枚举
 */
enum class EncodingType(val lengthRatio: Float) {
    BASE64(1.33f),
    BASE64_URL(1.33f),
    BASE64_NO_WRAP(1.33f),
    HEX(2.0f),
    URL_ENCODE(3.0f)
}

/**
 * 密钥格式枚举
 */
enum class KeyFormat {
    RAW,
    PKCS8,
    X509,
    PEM
}
