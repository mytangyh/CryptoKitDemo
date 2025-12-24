package com.example.cryptokit.registry

import com.example.cryptokit.core.asymmetric.AsymmetricCipher
import com.example.cryptokit.core.hash.HashEngine
import com.example.cryptokit.core.symmetric.SymmetricCipher

/**
 * 算法注册表
 */
object AlgorithmRegistry {

    private val symmetricCiphers = mutableMapOf<String, () -> SymmetricCipher>()
    private val asymmetricCiphers = mutableMapOf<String, () -> AsymmetricCipher>()
    private val hashEngines = mutableMapOf<String, () -> HashEngine>()

    /**
     * 注册对称加密算法
     */
    fun registerSymmetricCipher(name: String, factory: () -> SymmetricCipher) {
        symmetricCiphers[name.uppercase()] = factory
    }

    /**
     * 注册非对称加密算法
     */
    fun registerAsymmetricCipher(name: String, factory: () -> AsymmetricCipher) {
        asymmetricCiphers[name.uppercase()] = factory
    }

    /**
     * 注册哈希算法
     */
    fun registerHashEngine(name: String, factory: () -> HashEngine) {
        hashEngines[name.uppercase()] = factory
    }

    /**
     * 获取对称加密算法
     */
    fun getSymmetricCipher(name: String): SymmetricCipher? {
        return symmetricCiphers[name.uppercase()]?.invoke()
    }

    /**
     * 获取非对称加密算法
     */
    fun getAsymmetricCipher(name: String): AsymmetricCipher? {
        return asymmetricCiphers[name.uppercase()]?.invoke()
    }

    /**
     * 获取哈希算法
     */
    fun getHashEngine(name: String): HashEngine? {
        return hashEngines[name.uppercase()]?.invoke()
    }

    /**
     * 列出所有已注册的对称加密算法
     */
    fun listSymmetricCiphers(): List<String> = symmetricCiphers.keys.toList()

    /**
     * 列出所有已注册的非对称加密算法
     */
    fun listAsymmetricCiphers(): List<String> = asymmetricCiphers.keys.toList()

    /**
     * 列出所有已注册的哈希算法
     */
    fun listHashEngines(): List<String> = hashEngines.keys.toList()
}
