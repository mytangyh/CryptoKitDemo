package com.example.cryptokit.core.signature

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * RSA签名实现
 */
class RSASignature(
    override val algorithmName: String = "SHA256withRSA"
) : SignatureEngine {

    override fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = Signature.getInstance(algorithmName)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    override fun verify(data: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        val sig = Signature.getInstance(algorithmName)
        sig.initVerify(publicKey)
        sig.update(data)
        return sig.verify(signature)
    }

    companion object {
        fun sha256(): RSASignature = RSASignature("SHA256withRSA")
        fun sha384(): RSASignature = RSASignature("SHA384withRSA")
        fun sha512(): RSASignature = RSASignature("SHA512withRSA")
        fun sha1(): RSASignature = RSASignature("SHA1withRSA")
    }
}
