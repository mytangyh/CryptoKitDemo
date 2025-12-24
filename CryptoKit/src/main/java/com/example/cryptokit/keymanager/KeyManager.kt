package com.example.cryptokit.keymanager

import java.security.Key
import java.security.KeyPair
import javax.crypto.SecretKey

/**
 * 密钥管理器接口
 */
interface KeyManager {
    /**
     * 在Keystore中生成AES密钥
     */
    fun generateAESKeyInKeystore(
        alias: String,
        keySize: Int = 256,
        options: KeyStoreOptions = KeyStoreOptions()
    ): SecretKey

    /**
     * 在Keystore中生成RSA密钥对
     */
    fun generateRSAKeyPairInKeystore(
        alias: String,
        keySize: Int = 2048,
        options: KeyStoreOptions = KeyStoreOptions()
    ): KeyPair

    /**
     * 在Keystore中生成EC密钥对
     */
    fun generateECKeyPairInKeystore(
        alias: String,
        options: KeyStoreOptions = KeyStoreOptions()
    ): KeyPair

    /**
     * 获取密钥
     */
    fun getKey(alias: String): Key?

    /**
     * 获取密钥对
     */
    fun getKeyPair(alias: String): KeyPair?

    /**
     * 检查密钥是否存在
     */
    fun containsAlias(alias: String): Boolean

    /**
     * 删除密钥
     */
    fun deleteKey(alias: String): Boolean

    /**
     * 列出所有密钥别名
     */
    fun listAliases(): List<String>
}
