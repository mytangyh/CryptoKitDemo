package com.example.cryptokit.registry

import com.example.cryptokit.core.asymmetric.AsymmetricCipher
import com.example.cryptokit.core.asymmetric.RSACipher
import com.example.cryptokit.core.hash.HashEngine
import com.example.cryptokit.core.hash.StandardHashEngine
import com.example.cryptokit.core.symmetric.AESCipher
import com.example.cryptokit.core.symmetric.SymmetricCipher
import com.example.cryptokit.core.symmetric.TripleDESCipher
import java.util.concurrent.ConcurrentHashMap

/**
 * 算法注册表
 * 
 * 金融级特性：
 * - 线程安全（ConcurrentHashMap）
 * - 预注册默认算法
 * - 支持自定义算法扩展
 */
object AlgorithmRegistry {

    private val symmetricCiphers = ConcurrentHashMap<String, () -> SymmetricCipher>()
    private val asymmetricCiphers = ConcurrentHashMap<String, () -> AsymmetricCipher>()
    private val hashEngines = ConcurrentHashMap<String, () -> HashEngine>()
    
    init {
        // 预注册对称加密算法
        registerSymmetricCipher("AES-GCM") { AESCipher.gcm() }
        registerSymmetricCipher("AES-CBC") { AESCipher.cbc() }
        registerSymmetricCipher("AES-CTR") { AESCipher.ctr() }
        registerSymmetricCipher("3DES") { TripleDESCipher() }
        registerSymmetricCipher("3DES-CBC") { TripleDESCipher("CBC", "PKCS5Padding") }
        
        // 预注册非对称加密算法
        registerAsymmetricCipher("RSA-OAEP-SHA256") { RSACipher.oaepSha256() }
        registerAsymmetricCipher("RSA-OAEP-SHA1") { RSACipher.oaepSha1() }
        registerAsymmetricCipher("RSA-PKCS1") { RSACipher.pkcs1() }
        
        // 预注册哈希算法
        registerHashEngine("MD5") { StandardHashEngine.md5() }
        registerHashEngine("SHA-1") { StandardHashEngine.sha1() }
        registerHashEngine("SHA-256") { StandardHashEngine.sha256() }
        registerHashEngine("SHA-384") { StandardHashEngine.sha384() }
        registerHashEngine("SHA-512") { StandardHashEngine.sha512() }
    }

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
     * 注销对称加密算法
     */
    fun unregisterSymmetricCipher(name: String): Boolean {
        return symmetricCiphers.remove(name.uppercase()) != null
    }
    
    /**
     * 注销非对称加密算法
     */
    fun unregisterAsymmetricCipher(name: String): Boolean {
        return asymmetricCiphers.remove(name.uppercase()) != null
    }
    
    /**
     * 注销哈希算法
     */
    fun unregisterHashEngine(name: String): Boolean {
        return hashEngines.remove(name.uppercase()) != null
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
     * 检查对称加密算法是否已注册
     */
    fun hasSymmetricCipher(name: String): Boolean {
        return symmetricCiphers.containsKey(name.uppercase())
    }
    
    /**
     * 检查非对称加密算法是否已注册
     */
    fun hasAsymmetricCipher(name: String): Boolean {
        return asymmetricCiphers.containsKey(name.uppercase())
    }
    
    /**
     * 检查哈希算法是否已注册
     */
    fun hasHashEngine(name: String): Boolean {
        return hashEngines.containsKey(name.uppercase())
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
    
    /**
     * 重置为默认状态（清除自定义算法，保留默认算法）
     */
    fun reset() {
        symmetricCiphers.clear()
        asymmetricCiphers.clear()
        hashEngines.clear()
        
        // 重新注册默认算法
        registerSymmetricCipher("AES-GCM") { AESCipher.gcm() }
        registerSymmetricCipher("AES-CBC") { AESCipher.cbc() }
        registerSymmetricCipher("AES-CTR") { AESCipher.ctr() }
        registerSymmetricCipher("3DES") { TripleDESCipher() }
        
        registerAsymmetricCipher("RSA-OAEP-SHA256") { RSACipher.oaepSha256() }
        registerAsymmetricCipher("RSA-OAEP-SHA1") { RSACipher.oaepSha1() }
        registerAsymmetricCipher("RSA-PKCS1") { RSACipher.pkcs1() }
        
        registerHashEngine("MD5") { StandardHashEngine.md5() }
        registerHashEngine("SHA-1") { StandardHashEngine.sha1() }
        registerHashEngine("SHA-256") { StandardHashEngine.sha256() }
        registerHashEngine("SHA-384") { StandardHashEngine.sha384() }
        registerHashEngine("SHA-512") { StandardHashEngine.sha512() }
    }
}
