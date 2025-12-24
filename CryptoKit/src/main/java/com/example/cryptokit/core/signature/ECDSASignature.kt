package com.example.cryptokit.core.signature

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/**
 * ECDSA签名实现
 */
class ECDSASignature(
    override val algorithmName: String = "SHA256withECDSA"
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
        fun sha256(): ECDSASignature = ECDSASignature("SHA256withECDSA")
        fun sha384(): ECDSASignature = ECDSASignature("SHA384withECDSA")
        fun sha512(): ECDSASignature = ECDSASignature("SHA512withECDSA")
    }
}
