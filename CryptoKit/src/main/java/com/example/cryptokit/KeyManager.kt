package com.example.cryptokit

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * 密钥管理器 - 管理Android Keystore中的密钥
 */
object KeyManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    /**
     * 在Keystore中生成AES密钥
     */
    fun generateAESKeyInKeystore(
        alias: String,
        keySize: Int = 256,
        options: KeyGenOptions = KeyGenOptions()
    ): SecretKey {
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
            }
        }

        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    /**
     * 在Keystore中生成RSA密钥对
     */
    fun generateRSAKeyPairInKeystore(
        alias: String,
        keySize: Int = 2048,
        options: KeyGenOptions = KeyGenOptions()
    ): KeyPair {
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

        if (options.requireUserAuthentication) {
            builder.setUserAuthenticationRequired(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && options.isStrongBoxBacked) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (e: StrongBoxUnavailableException) {
                // StrongBox不可用
            }
        }

        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * 在Keystore中生成EC密钥对
     */
    fun generateECKeyPairInKeystore(
        alias: String,
        options: KeyGenOptions = KeyGenOptions()
    ): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                    KeyProperties.PURPOSE_AGREE_KEY
        )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)

        if (options.requireUserAuthentication) {
            builder.setUserAuthenticationRequired(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && options.isStrongBoxBacked) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (e: StrongBoxUnavailableException) {
                // StrongBox不可用
            }
        }

        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * 从Keystore获取密钥
     */
    fun getKey(alias: String): Key? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.getKey(alias, null)
    }

    /**
     * 从Keystore获取密钥对
     */
    fun getKeyPair(alias: String): KeyPair? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null
        
        return KeyPair(publicKey, privateKey)
    }

    /**
     * 检查密钥是否存在
     */
    fun containsAlias(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.containsAlias(alias)
    }

    /**
     * 删除密钥
     */
    fun deleteKey(alias: String): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(alias)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 列出所有密钥别名
     */
    fun listAliases(): List<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.aliases().toList()
    }
}
