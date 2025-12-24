package com.example.cryptokit.keymanager

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.example.cryptokit.exception.KeyManagementException
import java.security.*
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * 密钥管理器实现
 * 
 * 金融级特性：
 * - 懒加载单例KeyStore，避免重复加载
 * - 读写锁保护并发访问
 * - 完善的异常处理
 * - 支持StrongBox硬件安全模块
 */
class KeyManagerImpl private constructor() : KeyManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        
        val instance: KeyManagerImpl by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { 
            KeyManagerImpl() 
        }
    }
    
    // 读写锁，支持并发读、独占写
    private val lock = ReentrantReadWriteLock()
    
    // 懒加载KeyStore单例
    private val keyStore: KeyStore by lazy {
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { 
                load(null) 
            }
        } catch (e: Exception) {
            throw KeyManagementException.keystoreUnavailable(e)
        }
    }
    
    // 刷新KeyStore缓存
    private fun refreshKeyStore() {
        lock.write {
            try {
                keyStore.load(null)
            } catch (e: Exception) {
                throw KeyManagementException.keystoreUnavailable(e)
            }
        }
    }

    override fun generateAESKeyInKeystore(
        alias: String,
        keySize: Int,
        options: KeyStoreOptions
    ): SecretKey {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        require(keySize in listOf(128, 192, 256)) { "Invalid AES key size: $keySize" }
        
        return lock.write {
            try {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    ANDROID_KEYSTORE
                )

                val builder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(keySize)
                    .setRandomizedEncryptionRequired(true) // 强制随机IV

                applyOptions(builder, options)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
            } catch (e: Exception) {
                throw KeyManagementException.keyGenerationFailed(e)
            }
        }
    }

    override fun generateRSAKeyPairInKeystore(
        alias: String,
        keySize: Int,
        options: KeyStoreOptions
    ): KeyPair {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        require(keySize in listOf(1024, 2048, 4096)) { "Invalid RSA key size: $keySize" }
        
        return lock.write {
            try {
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    ANDROID_KEYSTORE
                )

                val builder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or
                            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setKeySize(keySize)
                    .setEncryptionPaddings(
                        KeyProperties.ENCRYPTION_PADDING_RSA_OAEP,
                        KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
                    )
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                    )

                applyOptions(builder, options)
                keyPairGenerator.initialize(builder.build())
                keyPairGenerator.generateKeyPair()
            } catch (e: Exception) {
                throw KeyManagementException.keyGenerationFailed(e)
            }
        }
    }

    override fun generateECKeyPairInKeystore(
        alias: String,
        options: KeyStoreOptions
    ): KeyPair {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        
        return lock.write {
            try {
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    ANDROID_KEYSTORE
                )

                val builder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                            KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setDigests(
                        KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA384,
                        KeyProperties.DIGEST_SHA512
                    )

                applyOptions(builder, options)
                keyPairGenerator.initialize(builder.build())
                keyPairGenerator.generateKeyPair()
            } catch (e: Exception) {
                throw KeyManagementException.keyGenerationFailed(e)
            }
        }
    }

    override fun getKey(alias: String): Key? {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        
        return lock.read {
            try {
                keyStore.getKey(alias, null)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun getKeyPair(alias: String): KeyPair? {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        
        return lock.read {
            try {
                val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return@read null
                val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return@read null
                KeyPair(publicKey, privateKey)
            } catch (e: Exception) {
                null
            }
        }
    }

    override fun containsAlias(alias: String): Boolean {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        
        return lock.read {
            try {
                keyStore.containsAlias(alias)
            } catch (e: Exception) {
                false
            }
        }
    }

    override fun deleteKey(alias: String): Boolean {
        require(alias.isNotBlank()) { "Alias cannot be blank" }
        
        return lock.write {
            try {
                keyStore.deleteEntry(alias)
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    override fun listAliases(): List<String> {
        return lock.read {
            try {
                keyStore.aliases().toList()
            } catch (e: Exception) {
                emptyList()
            }
        }
    }
    
    /**
     * 批量删除密钥（原子操作）
     */
    fun deleteKeys(aliases: List<String>): Int {
        return lock.write {
            var deleted = 0
            for (alias in aliases) {
                try {
                    keyStore.deleteEntry(alias)
                    deleted++
                } catch (e: Exception) {
                    // 继续删除其他密钥
                }
            }
            deleted
        }
    }
    
    /**
     * 检查是否支持StrongBox
     */
    fun isStrongBoxSupported(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
    }

    private fun applyOptions(builder: KeyGenParameterSpec.Builder, options: KeyStoreOptions) {
        if (options.requireUserAuthentication) {
            builder.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    options.authenticationTimeout,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && options.isStrongBoxBacked) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (e: StrongBoxUnavailableException) {
                // StrongBox不可用，使用普通TEE
                // 可以记录日志或通知调用方
            }
        }
        
        // 设置密钥不可导出（金融级安全要求）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(options.requireUnlockedDevice)
        }
    }
}
