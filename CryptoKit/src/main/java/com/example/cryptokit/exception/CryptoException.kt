package com.example.cryptokit.exception

/**
 * CryptoKit基础异常类
 * 
 * 金融级异常处理：
 * - 统一异常层次结构
 * - 详细错误信息
 * - 安全的错误消息（不泄露敏感信息）
 */
open class CryptoException(
    message: String,
    cause: Throwable? = null,
    val errorCode: ErrorCode = ErrorCode.UNKNOWN
) : Exception(message, cause) {
    
    /**
     * 获取安全的错误消息（不包含敏感信息，可用于日志或用户提示）
     */
    open fun getSafeMessage(): String = "Cryptographic operation failed: ${errorCode.description}"
}

/**
 * 加密异常
 */
class EncryptionException(
    message: String,
    cause: Throwable? = null,
    errorCode: ErrorCode = ErrorCode.ENCRYPTION_FAILED
) : CryptoException(message, cause, errorCode) {
    
    companion object {
        fun invalidKey(algorithm: String, cause: Throwable? = null): EncryptionException {
            return EncryptionException(
                "Invalid key for $algorithm encryption",
                cause,
                ErrorCode.INVALID_KEY
            )
        }
        
        fun invalidData(cause: Throwable? = null): EncryptionException {
            return EncryptionException(
                "Invalid plaintext data for encryption",
                cause,
                ErrorCode.INVALID_INPUT
            )
        }
        
        fun algorithmNotSupported(algorithm: String): EncryptionException {
            return EncryptionException(
                "Algorithm not supported: $algorithm",
                null,
                ErrorCode.ALGORITHM_NOT_SUPPORTED
            )
        }
    }
}

/**
 * 解密异常
 */
class DecryptionException(
    message: String,
    cause: Throwable? = null,
    errorCode: ErrorCode = ErrorCode.DECRYPTION_FAILED
) : CryptoException(message, cause, errorCode) {
    
    companion object {
        fun invalidKey(cause: Throwable? = null): DecryptionException {
            return DecryptionException(
                "Invalid key for decryption",
                cause,
                ErrorCode.INVALID_KEY
            )
        }
        
        fun invalidCiphertext(cause: Throwable? = null): DecryptionException {
            return DecryptionException(
                "Invalid or corrupted ciphertext",
                cause,
                ErrorCode.INVALID_CIPHERTEXT
            )
        }
        
        fun authenticationFailed(cause: Throwable? = null): DecryptionException {
            return DecryptionException(
                "Authentication tag verification failed (data may be tampered)",
                cause,
                ErrorCode.AUTH_TAG_MISMATCH
            )
        }
    }
}

/**
 * 签名异常
 */
class SignatureException(
    message: String,
    cause: Throwable? = null,
    errorCode: ErrorCode = ErrorCode.SIGNATURE_FAILED
) : CryptoException(message, cause, errorCode) {
    
    companion object {
        fun signFailed(cause: Throwable? = null): SignatureException {
            return SignatureException(
                "Failed to create digital signature",
                cause,
                ErrorCode.SIGNATURE_FAILED
            )
        }
        
        fun verifyFailed(cause: Throwable? = null): SignatureException {
            return SignatureException(
                "Signature verification failed",
                cause,
                ErrorCode.SIGNATURE_VERIFICATION_FAILED
            )
        }
    }
}

/**
 * 密钥管理异常
 */
class KeyManagementException(
    message: String,
    cause: Throwable? = null,
    errorCode: ErrorCode = ErrorCode.KEY_MANAGEMENT_ERROR
) : CryptoException(message, cause, errorCode) {
    
    companion object {
        fun keyNotFound(alias: String): KeyManagementException {
            return KeyManagementException(
                "Key not found with alias: $alias",
                null,
                ErrorCode.KEY_NOT_FOUND
            )
        }
        
        fun keyGenerationFailed(cause: Throwable? = null): KeyManagementException {
            return KeyManagementException(
                "Failed to generate key",
                cause,
                ErrorCode.KEY_GENERATION_FAILED
            )
        }
        
        fun keystoreUnavailable(cause: Throwable? = null): KeyManagementException {
            return KeyManagementException(
                "Android Keystore is unavailable",
                cause,
                ErrorCode.KEYSTORE_UNAVAILABLE
            )
        }
    }
}

/**
 * 输入验证异常
 */
class ValidationException(
    message: String,
    cause: Throwable? = null,
    errorCode: ErrorCode = ErrorCode.VALIDATION_FAILED
) : CryptoException(message, cause, errorCode) {
    
    companion object {
        fun invalidKeySize(expected: List<Int>, actual: Int): ValidationException {
            return ValidationException(
                "Invalid key size: $actual bits, expected one of: $expected",
                null,
                ErrorCode.INVALID_KEY_SIZE
            )
        }
        
        fun invalidIvSize(expected: Int, actual: Int): ValidationException {
            return ValidationException(
                "Invalid IV size: $actual bytes, expected: $expected",
                null,
                ErrorCode.INVALID_IV_SIZE
            )
        }
        
        fun emptyInput(): ValidationException {
            return ValidationException(
                "Input data cannot be empty",
                null,
                ErrorCode.EMPTY_INPUT
            )
        }
        
        fun nullParameter(paramName: String): ValidationException {
            return ValidationException(
                "Required parameter is null: $paramName",
                null,
                ErrorCode.NULL_PARAMETER
            )
        }
    }
}

/**
 * 错误码枚举
 */
enum class ErrorCode(val code: Int, val description: String) {
    UNKNOWN(1000, "Unknown error"),
    
    // 加密相关 1xxx
    ENCRYPTION_FAILED(1001, "Encryption operation failed"),
    DECRYPTION_FAILED(1002, "Decryption operation failed"),
    INVALID_KEY(1003, "Invalid cryptographic key"),
    INVALID_CIPHERTEXT(1004, "Invalid or corrupted ciphertext"),
    AUTH_TAG_MISMATCH(1005, "Authentication tag verification failed"),
    ALGORITHM_NOT_SUPPORTED(1006, "Cryptographic algorithm not supported"),
    
    // 签名相关 2xxx
    SIGNATURE_FAILED(2001, "Signature creation failed"),
    SIGNATURE_VERIFICATION_FAILED(2002, "Signature verification failed"),
    
    // 密钥管理 3xxx
    KEY_MANAGEMENT_ERROR(3001, "Key management operation failed"),
    KEY_NOT_FOUND(3002, "Key not found"),
    KEY_GENERATION_FAILED(3003, "Key generation failed"),
    KEYSTORE_UNAVAILABLE(3004, "Keystore unavailable"),
    
    // 验证相关 4xxx
    VALIDATION_FAILED(4001, "Input validation failed"),
    INVALID_KEY_SIZE(4002, "Invalid key size"),
    INVALID_IV_SIZE(4003, "Invalid IV size"),
    EMPTY_INPUT(4004, "Empty input data"),
    NULL_PARAMETER(4005, "Required parameter is null"),
    INVALID_INPUT(4006, "Invalid input data")
}
