package com.example.cryptokit.keymanager

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * 密钥管理器实现
 */
class KeyManagerImpl private constructor() : KeyManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        
        val instance: KeyManagerImpl by lazy { KeyManagerImpl() }
    }

    override fun generateAESKeyInKeystore(
        alias: String,
        keySize: Int,
        options: KeyStoreOptions
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

        applyOptions(builder, options)
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    override fun generateRSAKeyPairInKeystore(
        alias: String,
        keySize: Int,
        options: KeyStoreOptions
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

        applyOptions(builder, options)
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    override fun generateECKeyPairInKeystore(
        alias: String,
        options: KeyStoreOptions
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
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )

        applyOptions(builder, options)
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    override fun getKey(alias: String): Key? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.getKey(alias, null)
    }

    override fun getKeyPair(alias: String): KeyPair? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null

        return KeyPair(publicKey, privateKey)
    }

    override fun containsAlias(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.containsAlias(alias)
    }

    override fun deleteKey(alias: String): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(alias)
            true
        } catch (e: Exception) {
            false
        }
    }

    override fun listAliases(): List<String> {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.aliases().toList()
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
            }
        }
    }
}
