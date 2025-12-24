package com.example.cryptokit.api.builders

import com.example.cryptokit.exception.CryptoException
import com.example.cryptokit.exception.DecryptionException
import com.example.cryptokit.exception.EncryptionException
import com.example.cryptokit.exception.SignatureException
import com.example.cryptokit.exception.ValidationException

/**
 * Builder基类
 * 
 * 提供所有Builder共用的工具方法，减少代码重复
 */
abstract class BaseBuilder {
    
    /**
     * 验证字节数组非空
     */
    protected fun requireNotEmpty(data: ByteArray?, name: String = "data") {
        if (data == null || data.isEmpty()) {
            throw ValidationException.emptyInput()
        }
    }
    
    /**
     * 验证字符串非空
     */
    protected fun requireNotEmpty(data: String?, name: String = "data") {
        if (data.isNullOrEmpty()) {
            throw ValidationException.emptyInput()
        }
    }
    
    /**
     * 验证参数非空
     */
    protected fun <T> requireNotNull(value: T?, name: String): T {
        if (value == null) {
            throw ValidationException.nullParameter(name)
        }
        return value
    }
    
    /**
     * 验证值在允许列表中
     */
    protected fun <T> requireIn(value: T, allowed: List<T>, name: String) {
        if (value !in allowed) {
            throw ValidationException("Invalid $name: $value, allowed: $allowed")
        }
    }
    
    /**
     * 包装加密操作异常
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
 * 对称加密Builder基类
 */
abstract class SymmetricBuilder<T : SymmetricBuilder<T>> : BaseBuilder() {
    
    protected abstract fun self(): T
    
    protected var mode: String = "GCM"
    protected var padding: String = "NoPadding"
    
    /**
     * 设置加密模式
     */
    open fun mode(mode: String): T = self().apply { this.mode = mode.uppercase() }
    
    /**
     * 设置填充方案
     */
    open fun padding(padding: String): T = self().apply { this.padding = padding }
    
    /**
     * 验证密钥大小
     */
    protected fun validateKeySize(size: Int, validSizes: List<Int>, algorithm: String) {
        if (size !in validSizes) {
            throw ValidationException.invalidKeySize(validSizes, size)
        }
    }
    
    /**
     * 验证IV大小
     */
    protected fun validateIvSize(iv: ByteArray, expectedSize: Int) {
        if (iv.size != expectedSize) {
            throw ValidationException.invalidIvSize(expectedSize, iv.size)
        }
    }
}

/**
 * 非对称加密Builder基类
 */
abstract class AsymmetricBuilder<T : AsymmetricBuilder<T>> : BaseBuilder() {
    
    protected abstract fun self(): T
    
    protected var publicKey: java.security.PublicKey? = null
    protected var privateKey: java.security.PrivateKey? = null
    
    /**
     * 设置公钥
     */
    open fun publicKey(key: java.security.PublicKey): T = self().apply { 
        validatePublicKey(key)
        this.publicKey = key 
    }
    
    /**
     * 设置私钥
     */
    open fun privateKey(key: java.security.PrivateKey): T = self().apply { 
        validatePrivateKey(key)
        this.privateKey = key 
    }
    
    /**
     * 同时设置公钥和私钥
     */
    open fun keyPair(keyPair: java.security.KeyPair): T = self().apply {
        this.publicKey = keyPair.public
        this.privateKey = keyPair.private
    }
    
    /**
     * 验证公钥算法
     */
    protected open fun validatePublicKey(key: java.security.PublicKey) {
        val expectedAlgorithm = expectedKeyAlgorithm()
        if (key.algorithm != expectedAlgorithm) {
            throw ValidationException("Invalid public key algorithm: ${key.algorithm}, expected: $expectedAlgorithm")
        }
    }
    
    /**
     * 验证私钥算法
     */
    protected open fun validatePrivateKey(key: java.security.PrivateKey) {
        val expectedAlgorithm = expectedKeyAlgorithm()
        if (key.algorithm != expectedAlgorithm) {
            throw ValidationException("Invalid private key algorithm: ${key.algorithm}, expected: $expectedAlgorithm")
        }
    }
    
    /**
     * 预期的密钥算法
     */
    protected abstract fun expectedKeyAlgorithm(): String
    
    /**
     * 要求公钥已设置
     */
    protected fun requirePublicKey(): java.security.PublicKey {
        return requireNotNull(publicKey, "publicKey")
    }
    
    /**
     * 要求私钥已设置
     */
    protected fun requirePrivateKey(): java.security.PrivateKey {
        return requireNotNull(privateKey, "privateKey")
    }
}
