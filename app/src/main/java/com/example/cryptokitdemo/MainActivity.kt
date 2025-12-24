package com.example.cryptokitdemo

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.cryptokit.CryptoKit
import com.example.cryptokit.api.extensions.*
import java.security.KeyPair

class MainActivity : AppCompatActivity() {

    private lateinit var etInput: EditText
    private lateinit var tvAesResult: TextView
    private lateinit var tvRsaResult: TextView
    private lateinit var tvHybridResult: TextView
    private lateinit var tvSignResult: TextView
    private lateinit var tvHashResult: TextView
    private lateinit var tvEncodeResult: TextView
    private lateinit var tvEcdhResult: TextView

    // 保存RSA密钥对用于多个演示
    private var rsaKeyPair: KeyPair? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        initViews()
        setupListeners()
    }

    private fun initViews() {
        etInput = findViewById(R.id.etInput)
        tvAesResult = findViewById(R.id.tvAesResult)
        tvRsaResult = findViewById(R.id.tvRsaResult)
        tvHybridResult = findViewById(R.id.tvHybridResult)
        tvSignResult = findViewById(R.id.tvSignResult)
        tvHashResult = findViewById(R.id.tvHashResult)
        tvEncodeResult = findViewById(R.id.tvEncodeResult)
        tvEcdhResult = findViewById(R.id.tvEcdhResult)
    }

    private fun setupListeners() {
        // AES加密演示
        findViewById<Button>(R.id.btnAesEncrypt).setOnClickListener {
            demoAesEncryption()
        }

        // RSA加密演示
        findViewById<Button>(R.id.btnRsaEncrypt).setOnClickListener {
            demoRsaEncryption()
        }

        // 混合加密演示
        findViewById<Button>(R.id.btnHybridEncrypt).setOnClickListener {
            demoHybridEncryption()
        }

        // 签名演示
        findViewById<Button>(R.id.btnSign).setOnClickListener {
            demoDigitalSignature()
        }

        // 哈希演示
        findViewById<Button>(R.id.btnHash).setOnClickListener {
            demoHash()
        }

        // 编码演示
        findViewById<Button>(R.id.btnEncode).setOnClickListener {
            demoEncoding()
        }

        // ECDH密钥协商演示
        findViewById<Button>(R.id.btnEcdh).setOnClickListener {
            demoEcdh()
        }
    }

    /**
     * AES加密演示
     */
    private fun demoAesEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 零配置AES加密（默认AES-256-GCM）
            val result = CryptoKit.aes().encrypt(input)
            
            // 解密
            val decrypted = CryptoKit.aes().decryptToString(result)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ AES-256-GCM 加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("🔑 密钥 (Base64):")
                appendLine(result.key.encoded.toBase64NoWrap())
                appendLine()
                appendLine("🎲 IV (Hex):")
                appendLine(result.iv.toHex())
                appendLine()
                appendLine("🔒 密文 (Base64):")
                appendLine(result.ciphertext.toBase64NoWrap())
                appendLine()
                appendLine("📤 解密结果: $decrypted")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvAesResult.text = output
            showToast("AES加密成功")
        } catch (e: Exception) {
            tvAesResult.text = "❌ 错误: ${e.message}"
            showToast("AES加密失败")
        }
    }

    /**
     * RSA加密演示
     */
    private fun demoRsaEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 生成RSA密钥对（或使用已有的）
            if (rsaKeyPair == null) {
                rsaKeyPair = CryptoKit.rsa().generateKeyPair()
            }
            val keyPair = rsaKeyPair!!

            // 加密
            val encrypted = CryptoKit.rsa()
                .publicKey(keyPair.public)
                .encrypt(input)
            
            // 解密
            val decrypted = CryptoKit.rsa()
                .privateKey(keyPair.private)
                .decryptToString(encrypted)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ RSA-2048 加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("🔑 公钥 (前64字符):")
                appendLine(keyPair.public.encoded.toBase64NoWrap().take(64) + "...")
                appendLine()
                appendLine("🔒 密文 (Base64):")
                appendLine(encrypted.toBase64NoWrap())
                appendLine()
                appendLine("📤 解密结果: $decrypted")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvRsaResult.text = output
            showToast("RSA加密成功")
        } catch (e: Exception) {
            tvRsaResult.text = "❌ 错误: ${e.message}"
            showToast("RSA加密失败")
        }
    }

    /**
     * 混合加密演示（RSA+AES）
     */
    private fun demoHybridEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 生成RSA密钥对
            if (rsaKeyPair == null) {
                rsaKeyPair = CryptoKit.rsa().generateKeyPair()
            }
            val keyPair = rsaKeyPair!!

            // 混合加密
            val result = CryptoKit.hybrid()
                .publicKey(keyPair.public)
                .encrypt(input)
            
            // 混合解密
            val decrypted = CryptoKit.hybrid()
                .privateKey(keyPair.private)
                .decryptToString(result)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ 混合加密成功 (RSA+AES-256-GCM)")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("🔑 加密后的AES密钥 (Base64):")
                appendLine(result.encryptedKey.toBase64NoWrap())
                appendLine()
                appendLine("🎲 IV (Hex):")
                appendLine(result.iv.toHex())
                appendLine()
                appendLine("🔒 密文 (Base64):")
                appendLine(result.ciphertext.toBase64NoWrap())
                appendLine()
                appendLine("📤 解密结果: $decrypted")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvHybridResult.text = output
            showToast("混合加密成功")
        } catch (e: Exception) {
            tvHybridResult.text = "❌ 错误: ${e.message}"
            showToast("混合加密失败")
        }
    }

    /**
     * 数字签名演示
     */
    private fun demoDigitalSignature() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 生成RSA密钥对
            if (rsaKeyPair == null) {
                rsaKeyPair = CryptoKit.rsa().generateKeyPair()
            }
            val keyPair = rsaKeyPair!!

            // 签名
            val signature = CryptoKit.rsa()
                .privateKey(keyPair.private)
                .sign(input)
            
            // 验签
            val isValid = CryptoKit.rsa()
                .publicKey(keyPair.public)
                .verify(input, signature)

            // 测试篡改验证
            val tampered = CryptoKit.rsa()
                .publicKey(keyPair.public)
                .verify(input + " (篡改)", signature)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ RSA 数字签名演示")
                appendLine()
                appendLine("📄 原文: $input")
                appendLine()
                appendLine("✍️ 签名 (Base64):")
                appendLine(signature.toBase64NoWrap())
                appendLine()
                appendLine("✅ 验签结果: $isValid")
                appendLine("❌ 篡改后验签: $tampered")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvSignResult.text = output
            showToast("签名验证完成")
        } catch (e: Exception) {
            tvSignResult.text = "❌ 错误: ${e.message}"
            showToast("签名失败")
        }
    }

    /**
     * 哈希演示
     */
    private fun demoHash() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 计算各种哈希
            val md5 = CryptoKit.md5(input)
            val sha256 = CryptoKit.sha256(input)
            val sha512 = CryptoKit.sha512(input)
            
            // HMAC
            val hmacKey = CryptoKit.secureRandom(32)
            val hmac = CryptoKit.hmacToHex(input, hmacKey)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("# 哈希计算结果")
                appendLine()
                appendLine("📥 输入: $input")
                appendLine()
                appendLine("🔸 MD5:")
                appendLine(md5)
                appendLine()
                appendLine("🔹 SHA-256:")
                appendLine(sha256)
                appendLine()
                appendLine("🔷 SHA-512:")
                appendLine(sha512)
                appendLine()
                appendLine("🔐 HMAC-SHA256:")
                appendLine(hmac)
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvHashResult.text = output
            showToast("哈希计算完成")
        } catch (e: Exception) {
            tvHashResult.text = "❌ 错误: ${e.message}"
            showToast("哈希计算失败")
        }
    }

    /**
     * 编码演示
     */
    private fun demoEncoding() {
        try {
            val input = getInputText()
            val inputBytes = input.toByteArray(Charsets.UTF_8)

            // Base64编码
            val base64 = inputBytes.toBase64()
            val base64Url = inputBytes.toBase64Url()
            val base64NoWrap = inputBytes.toBase64NoWrap()
            
            // Hex编码
            val hex = inputBytes.toHex()
            
            // URL编码
            val urlEncoded = input.urlEncode()
            
            // 解码验证
            val decodedFromBase64 = base64.fromBase64()
            val decodedFromHex = hex.fromHex()

            val output = buildString {
                appendLine("📝 编码转换结果")
                appendLine()
                appendLine("📥 输入: $input")
                appendLine()
                appendLine("🔸 Base64:")
                appendLine(base64)
                appendLine()
                appendLine("🔹 Base64 URL Safe:")
                appendLine(base64Url)
                appendLine()
                appendLine("🔷 Base64 No Wrap:")
                appendLine(base64NoWrap)
                appendLine()
                appendLine("🔶 Hex:")
                appendLine(hex)
                appendLine()
                appendLine("🔗 URL Encode:")
                appendLine(urlEncoded)
                appendLine()
                appendLine("✅ Base64解码验证: ${String(decodedFromBase64)}")
                appendLine("✅ Hex解码验证: ${String(decodedFromHex)}")
            }
            
            tvEncodeResult.text = output
            showToast("编码完成")
        } catch (e: Exception) {
            tvEncodeResult.text = "❌ 错误: ${e.message}"
            showToast("编码失败")
        }
    }

    /**
     * ECDH密钥协商演示
     */
    private fun demoEcdh() {
        try {
            val startTime = System.currentTimeMillis()

            // 模拟Alice和Bob两方
            val aliceBuilder = CryptoKit.ecc().p256()
            val bobBuilder = CryptoKit.ecc().p256()
            
            val aliceKeyPair = aliceBuilder.generateKeyPair()
            val bobKeyPair = bobBuilder.generateKeyPair()
            
            // Alice计算共享密钥
            val aliceSharedSecret = CryptoKit.ecc()
                .privateKey(aliceKeyPair.private)
                .deriveSharedSecret(bobKeyPair.public)
            
            // Bob计算共享密钥
            val bobSharedSecret = CryptoKit.ecc()
                .privateKey(bobKeyPair.private)
                .deriveSharedSecret(aliceKeyPair.public)
            
            // 验证共享密钥是否相同
            val isEqual = aliceSharedSecret.contentEquals(bobSharedSecret)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("🤝 ECDH 密钥协商演示 (P-256)")
                appendLine()
                appendLine("👩 Alice公钥 (前32字符):")
                appendLine(aliceKeyPair.public.encoded.toHex().take(32) + "...")
                appendLine()
                appendLine("👨 Bob公钥 (前32字符):")
                appendLine(bobKeyPair.public.encoded.toHex().take(32) + "...")
                appendLine()
                appendLine("🔑 Alice计算的共享密钥:")
                appendLine(aliceSharedSecret.toHex())
                appendLine()
                appendLine("🔑 Bob计算的共享密钥:")
                appendLine(bobSharedSecret.toHex())
                appendLine()
                appendLine("✅ 共享密钥一致: $isEqual")
                appendLine()
                appendLine("💡 可以使用此共享密钥进行AES加密通信")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvEcdhResult.text = output
            showToast("ECDH密钥协商成功")
        } catch (e: Exception) {
            tvEcdhResult.text = "❌ 错误: ${e.message}"
            showToast("ECDH密钥协商失败")
        }
    }

    private fun getInputText(): String {
        val text = etInput.text.toString()
        if (text.isBlank()) {
            throw IllegalArgumentException("请输入内容")
        }
        return text
    }

    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}