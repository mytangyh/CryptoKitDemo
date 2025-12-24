package com.example.cryptokitdemo

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
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
    private lateinit var tvDesResult: TextView
    private lateinit var tvRsaResult: TextView
    private lateinit var tvHybridResult: TextView
    private lateinit var tvSignResult: TextView
    private lateinit var tvHashResult: TextView
    private lateinit var tvEncodeResult: TextView
    private lateinit var tvEcdhResult: TextView

    // RadioGroups
    private lateinit var rgAesMode: RadioGroup
    private lateinit var rgAesKeySize: RadioGroup
    private lateinit var rgDesMode: RadioGroup
    private lateinit var rgRsaKeySize: RadioGroup
    private lateinit var rgRsaPadding: RadioGroup
    private lateinit var rgSignType: RadioGroup
    private lateinit var rgHashAlgorithm: RadioGroup
    private lateinit var rgEccCurve: RadioGroup

    // 缓存密钥对
    private var rsaKeyPairs = mutableMapOf<Int, KeyPair>()
    private var eccKeyPairs = mutableMapOf<String, KeyPair>()

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
        tvDesResult = findViewById(R.id.tvDesResult)
        tvRsaResult = findViewById(R.id.tvRsaResult)
        tvHybridResult = findViewById(R.id.tvHybridResult)
        tvSignResult = findViewById(R.id.tvSignResult)
        tvHashResult = findViewById(R.id.tvHashResult)
        tvEncodeResult = findViewById(R.id.tvEncodeResult)
        tvEcdhResult = findViewById(R.id.tvEcdhResult)

        // RadioGroups
        rgAesMode = findViewById(R.id.rgAesMode)
        rgAesKeySize = findViewById(R.id.rgAesKeySize)
        rgDesMode = findViewById(R.id.rgDesMode)
        rgRsaKeySize = findViewById(R.id.rgRsaKeySize)
        rgRsaPadding = findViewById(R.id.rgRsaPadding)
        rgSignType = findViewById(R.id.rgSignType)
        rgHashAlgorithm = findViewById(R.id.rgHashAlgorithm)
        rgEccCurve = findViewById(R.id.rgEccCurve)
    }

    private fun setupListeners() {
        findViewById<Button>(R.id.btnAesEncrypt).setOnClickListener { demoAesEncryption() }
        findViewById<Button>(R.id.btnDesEncrypt).setOnClickListener { demoTripleDesEncryption() }
        findViewById<Button>(R.id.btnRsaEncrypt).setOnClickListener { demoRsaEncryption() }
        findViewById<Button>(R.id.btnHybridEncrypt).setOnClickListener { demoHybridEncryption() }
        findViewById<Button>(R.id.btnSign).setOnClickListener { demoDigitalSignature() }
        findViewById<Button>(R.id.btnHash).setOnClickListener { demoHash() }
        findViewById<Button>(R.id.btnEncode).setOnClickListener { demoEncoding() }
        findViewById<Button>(R.id.btnEcdh).setOnClickListener { demoEcdh() }
    }

    // ==================== AES加密演示 ====================
    private fun demoAesEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 获取选择的模式
            val mode = when (rgAesMode.checkedRadioButtonId) {
                R.id.rbAesGcm -> "GCM"
                R.id.rbAesCbc -> "CBC"
                R.id.rbAesCtr -> "CTR"
                else -> "GCM"
            }

            // 获取选择的密钥长度
            val keySize = when (rgAesKeySize.checkedRadioButtonId) {
                R.id.rbAes128 -> 128
                R.id.rbAes192 -> 192
                R.id.rbAes256 -> 256
                else -> 256
            }

            // 构建AES加密器
            val aesBuilder = CryptoKit.aes()
                .keySize(keySize)
                .apply {
                    when (mode) {
                        "GCM" -> gcm()
                        "CBC" -> cbc()
                        "CTR" -> ctr()
                    }
                }

            // 加密
            val result = aesBuilder.encrypt(input)
            
            // 解密
            val decrypted = CryptoKit.aes().decryptToString(result)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ AES-${keySize}-${mode} 加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("⚙️ 配置: 模式=$mode, 密钥=${keySize}位")
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
            showToast("AES-${keySize}-${mode} 加密成功")
        } catch (e: Exception) {
            tvAesResult.text = "❌ 错误: ${e.message}"
            showToast("AES加密失败")
        }
    }

    // ==================== 3DES加密演示 ====================
    private fun demoTripleDesEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 获取选择的模式
            val mode = when (rgDesMode.checkedRadioButtonId) {
                R.id.rbDesCbc -> "CBC"
                R.id.rbDesEcb -> "ECB"
                else -> "CBC"
            }

            // 构建3DES加密器
            val desBuilder = CryptoKit.tripleDes().apply {
                when (mode) {
                    "CBC" -> cbc()
                    "ECB" -> ecb()
                }
            }

            // 加密
            val result = desBuilder.encrypt(input)
            
            // 解密
            val decrypted = CryptoKit.tripleDes().decryptToString(result)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ 3DES-${mode} 加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("⚙️ 配置: 模式=$mode, 密钥=168位")
                appendLine()
                appendLine("⚠️ 注意: 3DES仅用于兼容旧系统，新项目请使用AES")
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
            
            tvDesResult.text = output
            showToast("3DES-${mode} 加密成功")
        } catch (e: Exception) {
            tvDesResult.text = "❌ 错误: ${e.message}"
            showToast("3DES加密失败")
        }
    }

    // ==================== RSA加密演示 ====================
    private fun demoRsaEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 获取选择的密钥长度
            val keySize = when (rgRsaKeySize.checkedRadioButtonId) {
                R.id.rbRsa1024 -> 1024
                R.id.rbRsa2048 -> 2048
                R.id.rbRsa4096 -> 4096
                else -> 2048
            }

            // 获取选择的填充方案
            val paddingName = when (rgRsaPadding.checkedRadioButtonId) {
                R.id.rbRsaOaep256 -> "OAEP-SHA256"
                R.id.rbRsaOaep1 -> "OAEP-SHA1"
                R.id.rbRsaPkcs1 -> "PKCS1"
                else -> "OAEP-SHA256"
            }

            // 获取或生成对应密钥长度的密钥对
            val keyPair = rsaKeyPairs.getOrPut(keySize) {
                CryptoKit.rsa().keySize(keySize).generateKeyPair()
            }

            // 构建RSA加密器
            val rsaBuilder = CryptoKit.rsa()
                .keySize(keySize)
                .apply {
                    when (paddingName) {
                        "OAEP-SHA256" -> oaepSha256()
                        "OAEP-SHA1" -> oaepSha1()
                        "PKCS1" -> pkcs1()
                    }
                }

            // 加密
            val encrypted = rsaBuilder
                .publicKey(keyPair.public)
                .encrypt(input)
            
            // 解密
            val decrypted = rsaBuilder
                .privateKey(keyPair.private)
                .decryptToString(encrypted)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("✅ RSA-${keySize} 加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("⚙️ 配置: 密钥=${keySize}位, 填充=$paddingName")
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
            showToast("RSA-${keySize} 加密成功")
        } catch (e: Exception) {
            tvRsaResult.text = "❌ 错误: ${e.message}"
            showToast("RSA加密失败")
        }
    }

    // ==================== 混合加密演示 ====================
    private fun demoHybridEncryption() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 使用2048位RSA密钥
            val keyPair = rsaKeyPairs.getOrPut(2048) {
                CryptoKit.rsa().keySize(2048).generateKeyPair()
            }

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
                appendLine("✅ 混合加密成功 (RSA-2048 + AES-256-GCM)")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("💡 原理: AES加密数据, RSA加密AES密钥")
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

    // ==================== 数字签名演示 ====================
    private fun demoDigitalSignature() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            val signType = when (rgSignType.checkedRadioButtonId) {
                R.id.rbSignRsa -> "RSA"
                R.id.rbSignEcdsa -> "ECDSA"
                else -> "RSA"
            }

            val output: String

            if (signType == "RSA") {
                // RSA签名
                val keyPair = rsaKeyPairs.getOrPut(2048) {
                    CryptoKit.rsa().keySize(2048).generateKeyPair()
                }

                val signature = CryptoKit.rsa()
                    .privateKey(keyPair.private)
                    .sign(input)
                
                val isValid = CryptoKit.rsa()
                    .publicKey(keyPair.public)
                    .verify(input, signature)

                val tampered = CryptoKit.rsa()
                    .publicKey(keyPair.public)
                    .verify(input + " (篡改)", signature)

                val duration = System.currentTimeMillis() - startTime

                output = buildString {
                    appendLine("✅ RSA-SHA256 数字签名")
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
            } else {
                // ECDSA签名
                val keyPair = eccKeyPairs.getOrPut("P-256") {
                    CryptoKit.ecc().p256().generateKeyPair()
                }

                val signature = CryptoKit.ecc()
                    .p256()
                    .privateKey(keyPair.private)
                    .sign(input)
                
                val isValid = CryptoKit.ecc()
                    .p256()
                    .publicKey(keyPair.public)
                    .verify(input, signature)

                val tampered = CryptoKit.ecc()
                    .p256()
                    .publicKey(keyPair.public)
                    .verify(input + " (篡改)", signature)

                val duration = System.currentTimeMillis() - startTime

                output = buildString {
                    appendLine("✅ ECDSA-SHA256 (P-256) 数字签名")
                    appendLine()
                    appendLine("📄 原文: $input")
                    appendLine()
                    appendLine("✍️ 签名 (Base64):")
                    appendLine(signature.toBase64NoWrap())
                    appendLine()
                    appendLine("✅ 验签结果: $isValid")
                    appendLine("❌ 篡改后验签: $tampered")
                    appendLine()
                    appendLine("⏱️ 耗时: ${System.currentTimeMillis() - startTime}ms")
                }
            }
            
            tvSignResult.text = output
            showToast("$signType 签名验证完成")
        } catch (e: Exception) {
            tvSignResult.text = "❌ 错误: ${e.message}"
            showToast("签名失败")
        }
    }

    // ==================== 哈希演示 ====================
    private fun demoHash() {
        try {
            val input = getInputText()
            val startTime = System.currentTimeMillis()

            // 获取选择的算法
            val algorithm = when (rgHashAlgorithm.checkedRadioButtonId) {
                R.id.rbHashMd5 -> "MD5"
                R.id.rbHashSha1 -> "SHA-1"
                R.id.rbHashSha256 -> "SHA-256"
                R.id.rbHashSha512 -> "SHA-512"
                else -> "SHA-256"
            }

            // 计算哈希
            val hashBuilder = CryptoKit.hash(algorithm)
            val hash = hashBuilder.digestToHex(input)
            
            // HMAC
            val hmacKey = CryptoKit.secureRandom(32)
            val hmac = hashBuilder.hmacToHex(input, hmacKey)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("# $algorithm 哈希计算结果")
                appendLine()
                appendLine("📥 输入: $input")
                appendLine()
                appendLine("🔹 $algorithm 哈希值:")
                appendLine(hash)
                appendLine()
                appendLine("🔐 HMAC-$algorithm:")
                appendLine(hmac)
                appendLine()
                appendLine("📊 哈希长度: ${hash.length / 2} 字节")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvHashResult.text = output
            showToast("$algorithm 哈希计算完成")
        } catch (e: Exception) {
            tvHashResult.text = "❌ 错误: ${e.message}"
            showToast("哈希计算失败")
        }
    }

    // ==================== 编码演示 ====================
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
                appendLine("🔸 Base64 (标准):")
                appendLine(base64)
                appendLine()
                appendLine("🔹 Base64 (URL安全):")
                appendLine(base64Url)
                appendLine()
                appendLine("🔷 Base64 (无换行):")
                appendLine(base64NoWrap)
                appendLine()
                appendLine("🔶 Hex:")
                appendLine(hex)
                appendLine()
                appendLine("🔗 URL编码:")
                appendLine(urlEncoded)
                appendLine()
                appendLine("✅ Base64解码: ${String(decodedFromBase64)}")
                appendLine("✅ Hex解码: ${String(decodedFromHex)}")
            }
            
            tvEncodeResult.text = output
            showToast("编码完成")
        } catch (e: Exception) {
            tvEncodeResult.text = "❌ 错误: ${e.message}"
            showToast("编码失败")
        }
    }

    // ==================== ECDH密钥协商演示 ====================
    private fun demoEcdh() {
        try {
            val startTime = System.currentTimeMillis()

            // 获取选择的曲线
            val curveName = when (rgEccCurve.checkedRadioButtonId) {
                R.id.rbEccP256 -> "P-256"
                R.id.rbEccP384 -> "P-384"
                R.id.rbEccP521 -> "P-521"
                else -> "P-256"
            }

            // 创建对应曲线的Builder
            val eccBuilder = when (curveName) {
                "P-256" -> CryptoKit.ecc().p256()
                "P-384" -> CryptoKit.ecc().p384()
                "P-521" -> CryptoKit.ecc().p521()
                else -> CryptoKit.ecc().p256()
            }

            // 模拟Alice和Bob两方
            val aliceKeyPair = eccBuilder.generateKeyPair()
            val bobKeyPair = when (curveName) {
                "P-256" -> CryptoKit.ecc().p256().generateKeyPair()
                "P-384" -> CryptoKit.ecc().p384().generateKeyPair()
                "P-521" -> CryptoKit.ecc().p521().generateKeyPair()
                else -> CryptoKit.ecc().p256().generateKeyPair()
            }
            
            // Alice计算共享密钥
            val aliceSharedSecret = when (curveName) {
                "P-256" -> CryptoKit.ecc().p256()
                "P-384" -> CryptoKit.ecc().p384()
                "P-521" -> CryptoKit.ecc().p521()
                else -> CryptoKit.ecc().p256()
            }.privateKey(aliceKeyPair.private).deriveSharedSecret(bobKeyPair.public)
            
            // Bob计算共享密钥
            val bobSharedSecret = when (curveName) {
                "P-256" -> CryptoKit.ecc().p256()
                "P-384" -> CryptoKit.ecc().p384()
                "P-521" -> CryptoKit.ecc().p521()
                else -> CryptoKit.ecc().p256()
            }.privateKey(bobKeyPair.private).deriveSharedSecret(aliceKeyPair.public)
            
            // 验证共享密钥是否相同
            val isEqual = aliceSharedSecret.contentEquals(bobSharedSecret)
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("🤝 ECDH 密钥协商演示 ($curveName)")
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
                appendLine("📊 共享密钥长度: ${aliceSharedSecret.size} 字节")
                appendLine()
                appendLine("💡 可以使用此共享密钥进行AES加密通信")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvEcdhResult.text = output
            showToast("ECDH-$curveName 密钥协商成功")
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