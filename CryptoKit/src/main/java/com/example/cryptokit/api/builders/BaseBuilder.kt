package com.example.cryptokit.api.builders

import com.example.cryptokit.exception.CryptoException
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.SignatureException
import com.example.cryptokit.exception.ValidationException

/**
 * # Builder 基类
 *
 * 提供所有 Builder 共用的工具方法，包括输入验证和异常包装。
 *
 * ## 主要功能
 *
 * - **输入验证**: [requireNotEmpty], [requireNotNull], [requireIn]
 * - **异常包装**: [wrapEncryptionException], [wrapDecryptionException], [wrapSignatureException]
 *
 * @since 1.0.0
 */
abstract class BaseBuilder {
    
    /**
     * 验证字节数组非空
     *
     * @param data 要验证的数据
     * @param name 参数名（用于错误消息）
     * @throws ValidationException 数据为空
     */
    protected fun requireNotEmpty(data: ByteArray?, name: String = "data") {
        if (data == null || data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
    }
    
    /**
     * 验证字符串非空
     *
     * @param data 要验证的字符串
     * @param name 参数名
     * @throws ValidationException 字符串为空
     */
    protected fun requireNotEmpty(data: String?, name: String = "data") {
        if (data.isNullOrEmpty()) {
            throw ValidationException.emptyInput()
        }
    }
    
    /**
     * 验证参数非空
     *
     * @param value 要验证的值
     * @param name 参数名
     * @return 非空值
     * @throws ValidationException 值为空
     */
    protected fun <T> requireNotNull(value: T?, name: String): T {
        if (value == null) {
            throw ValidationException.nullParameter(name)
        }
        return value
    }
    
    /**
     * 验证值在允许列表中
     *
     * @param value 要验证的值
     * @param allowed 允许的值列表
     * @param name 参数名
     * @throws ValidationException 值不在列表中
     */
    protected fun <T> requireIn(value: T, allowed: List<T>, name: String) {
        if (value !in allowed) {
            throw ValidationException("Invalid $name: $value, allowed: $allowed")
        }
    }
    
    /**
     * 包装加密操作异常
     *
     * 将底层异常转换为 [EncryptionException]。
     *
     * @param algorithm 算法名称
     * @param block 加密操作
     * @return 操作结果
     * @throws EncryptionException 加密失败
     */
    protected inline fun <R> wrapEncryptionException(
        algorithm: String,
        block: () -> R
    ): R = try {
        block()
    } catch (e: ValidationException) {
        throw e
    } catch (e: Exception) {
        throw EncryptionException("$algorithm encryption failed: ${e.message}", e)
    }
    
    /**
     * 包装解密操作异常
     *
     * 将底层异常转换为 [DecryptionException]。
     * 特别处理 GCM 认证失败异常。
     *
     * @param algorithm 算法名称
     * @param block 解密操作
     * @return 操作结果
     * @throws DecryptionException 解密失败
     */
    protected inline fun <R> wrapDecryptionException(
        algorithm: String,
        block: () -> R
    ): R = try {
        block()
    } catch (e: ValidationException) {
        throw e
    } catch (e: javax.crypto.AEADBadTagException) {
        throw DecryptionException.authenticationFailed(e)
    } catch (e: Exception) {
        throw DecryptionException("$algorithm decryption failed: ${e.message}", e)
    }
    
    /**
     * 包装签名操作异常
     *
     * @param operation 操作类型："sign" 或 "verify"
     * @param block 签名操作
     * @return 操作结果
     * @throws SignatureException 签名失败
     */
    protected inline fun <R> wrapSignatureException(
        operation: String,
        block: () -> R
    ): R = try {
        block()
    } catch (e: ValidationException) {
        throw e
    } catch (e: Exception) {
        when (operation) {
            "sign" -> throw SignatureException.signFailed(e)
            "verify" -> throw SignatureException.verifyFailed(e)
            else -> throw CryptoException("$operation failed: ${e.message}", e)
        }
    }
    
    /**
     * 包装通用加密操作异常
     *
     * @param operation 操作描述
     * @param block 操作
     * @return 操作结果
     * @throws CryptoException 操作失败
     */
    protected inline fun <R> wrapCryptoException(
        operation: String,
        block: () -> R
    ): R = try {
        block()
    } catch (e: ValidationException) {
        throw e
    } catch (e: CryptoException) {
        throw e
    } catch (e: Exception) {
        throw CryptoException("$operation failed: ${e.message}", e)
    }
}

/**
 * # 对称加密 Builder 基类
 *
 * 为对称加密 Builder 提供公共功能，包括模式、填充配置和密钥/IV 验证。
 *
 * ## 子类
 *
 * - [AESBuilder]
 * - [TripleDESBuilder]
 *
 * @param T 子类类型（用于方法链）
 * @since 1.0.0
 */
abstract class SymmetricBuilder<T : SymmetricBuilder<T>> : BaseBuilder() {
    
    /**
     * 返回子类实例（用于方法链）
     */
    protected abstract fun self(): T
    
    /** 加密模式 */
    protected var mode: String = "GCM"
    
    /** 填充方案 */
    protected var padding: String = "NoPadding"
    
    /**
     * 设置加密模式
     *
     * @param mode 加密模式
     * @return this
     */
    open fun mode(mode: String): T = self().apply { this.mode = mode.uppercase() }
    
    /**
     * 设置填充方案
     *
     * @param padding 填充方案
     * @return this
     */
    open fun padding(padding: String): T = self().apply { this.padding = padding }
    
    /**
     * 验证密钥大小
     *
     * @param size 密钥大小（位）
     * @param validSizes 有效的密钥大小列表
     * @param algorithm 算法名称
     * @throws ValidationException 无效的密钥大小
     */
    protected fun validateKeySize(size: Int, validSizes: List<Int>, algorithm: String) {
        if (size !in validSizes) {
            throw ValidationException.invalidKeySize(validSizes, size)
        }
    }
    
    /**
     * 验证 IV 大小
     *
     * @param iv IV 字节数组
     * @param expectedSize 预期大小（字节）
     * @throws ValidationException 无效的 IV 大小
     */
    protected fun validateIvSize(iv: ByteArray, expectedSize: Int) {
        if (iv.size != expectedSize) {
            throw ValidationException.invalidIvSize(expectedSize, iv.size)
        }
    }
}

/**
 * # 非对称加密 Builder 基类
 *
 * 为非对称加密 Builder 提供公共功能，包括公钥/私钥管理和验证。
 *
 * ## 子类
 *
 * - [RSABuilder]
 * - [ECCBuilder]
 * - [HybridBuilder]
 *
 * @param T 子类类型（用于方法链）
 * @since 1.0.0
 */
abstract class AsymmetricBuilder<T : AsymmetricBuilder<T>> : BaseBuilder() {
    
    /**
     * 返回子类实例（用于方法链）
     */
    protected abstract fun self(): T
    
    /** 公钥 */
    protected var publicKey: java.security.PublicKey? = null
    
    /** 私钥 */
    protected var privateKey: java.security.PrivateKey? = null
    
    /**
     * 设置公钥
     *
     * @param key 公钥
     * @return this
     * @throws ValidationException 无效的公钥
     */
    open fun publicKey(key: java.security.PublicKey): T = self().apply { 
        validatePublicKey(key)
        this.publicKey = key 
    }
    
    /**
     * 设置私钥
     *
     * @param key 私钥
     * @return this
     * @throws ValidationException 无效的私钥
     */
    open fun privateKey(key: java.security.PrivateKey): T = self().apply { 
        validatePrivateKey(key)
        this.privateKey = key 
    }
    
    /**
     * 同时设置公钥和私钥
     *
     * @param keyPair 密钥对
     * @return this
     */
    open fun keyPair(keyPair: java.security.KeyPair): T = self().apply {
        this.publicKey = keyPair.public
        this.privateKey = keyPair.private
    }
    
    /**
     * 验证公钥算法
     *
     * @param key 要验证的公钥
     * @throws ValidationException 算法不匹配
     */
    protected open fun validatePublicKey(key: java.security.PublicKey) {
        val expectedAlgorithm = expectedKeyAlgorithm()
        if (key.algorithm != expectedAlgorithm) {
            throw ValidationException("Invalid public key algorithm: ${key.algorithm}, expected: $expectedAlgorithm")
        }
    }
    
    /**
     * 验证私钥算法
     *
     * @param key 要验证的私钥
     * @throws ValidationException 算法不匹配
     */
    protected open fun validatePrivateKey(key: java.security.PrivateKey) {
        val expectedAlgorithm = expectedKeyAlgorithm()
        if (key.algorithm != expectedAlgorithm) {
            throw ValidationException("Invalid private key algorithm: ${key.algorithm}, expected: $expectedAlgorithm")
        }
    }
    
    /**
     * 返回预期的密钥算法
     *
     * @return 算法名称，如 "RSA" 或 "EC"
     */
    protected abstract fun expectedKeyAlgorithm(): String
    
    /**
     * 获取公钥，如果未设置则抛出异常
     *
     * @return 公钥
     * @throws ValidationException 公钥未设置
     */
    protected fun requirePublicKey(): java.security.PublicKey {
        return requireNotNull(publicKey, "publicKey")
    }
    
    /**
     * 获取私钥，如果未设置则抛出异常
     *
     * @return 私钥
     * @throws ValidationException 私钥未设置
     */
    protected fun requirePrivateKey(): java.security.PrivateKey {
        return requireNotNull(privateKey, "privateKey")
    }
}
