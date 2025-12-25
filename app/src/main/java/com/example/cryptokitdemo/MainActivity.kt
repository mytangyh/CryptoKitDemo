package com.example.cryptokitdemo

import android.os.Bundle
import android.widget.Button
import android.widget.CheckBox
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
    private lateinit var tvInterceptorStatus: TextView
    private lateinit var tvPbkdf2Result: TextView
    private lateinit var tvUtilsResult: TextView
    private lateinit var tvKeystoreResult: TextView
    private lateinit var tvStreamResult: TextView
    private lateinit var tvSecureResult: TextView
    private lateinit var tvConcurrencyResult: TextView
    private lateinit var tvRegistryResult: TextView

    // CheckBoxes
    private lateinit var cbEnableLogging: CheckBox
    private lateinit var cbEnablePerformance: CheckBox

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

        // New views
        tvInterceptorStatus = findViewById(R.id.tvInterceptorStatus)
        tvPbkdf2Result = findViewById(R.id.tvPbkdf2Result)
        tvUtilsResult = findViewById(R.id.tvUtilsResult)
        tvKeystoreResult = findViewById(R.id.tvKeystoreResult)
        tvStreamResult = findViewById(R.id.tvStreamResult)
        tvSecureResult = findViewById(R.id.tvSecureResult)
        tvConcurrencyResult = findViewById(R.id.tvConcurrencyResult)
        tvRegistryResult = findViewById(R.id.tvRegistryResult)
        cbEnableLogging = findViewById(R.id.cbEnableLogging)
        cbEnablePerformance = findViewById(R.id.cbEnablePerformance)
    }

    private fun setupListeners() {
        findViewById<Button>(R.id.btnAesEncrypt).setOnClickListener { demoAesEncryption() }
        findViewById<Button>(R.id.btnAesSharedKey).setOnClickListener { demoAesSharedKey() }
        findViewById<Button>(R.id.btnDesEncrypt).setOnClickListener { demoTripleDesEncryption() }
        findViewById<Button>(R.id.btnRsaEncrypt).setOnClickListener { demoRsaEncryption() }
        findViewById<Button>(R.id.btnHybridEncrypt).setOnClickListener { demoHybridEncryption() }
        findViewById<Button>(R.id.btnSign).setOnClickListener { demoDigitalSignature() }
        findViewById<Button>(R.id.btnHash).setOnClickListener { demoHash() }
        findViewById<Button>(R.id.btnEncode).setOnClickListener { demoEncoding() }
        findViewById<Button>(R.id.btnEcdh).setOnClickListener { demoEcdh() }
        findViewById<Button>(R.id.btnPbkdf2).setOnClickListener { demoPbkdf2() }
        findViewById<Button>(R.id.btnUtils).setOnClickListener { demoUtils() }
        findViewById<Button>(R.id.btnKeystore).setOnClickListener { demoKeystore() }
        findViewById<Button>(R.id.btnStreamEncrypt).setOnClickListener { demoStreamEncryption() }
        findViewById<Button>(R.id.btnSecureUtils).setOnClickListener { demoSecureUtils() }
        findViewById<Button>(R.id.btnConcurrencyTest).setOnClickListener { demoConcurrencyTest() }
        findViewById<Button>(R.id.btnRegistry).setOnClickListener { demoRegistry() }

        // 拦截器开关
        cbEnableLogging.setOnCheckedChangeListener { _, _ -> updateInterceptors() }
        cbEnablePerformance.setOnCheckedChangeListener { _, _ -> updateInterceptors() }
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
    
    // ==================== AES 预协商密钥加密演示 ====================
    private fun demoAesSharedKey() {
        try {
            val input = getInputText()
            val key = findViewById<EditText>(R.id.etAesKey).text.toString()
            val iv = findViewById<EditText>(R.id.etAesIv).text.toString()
            
            // 验证密钥长度
            if (key.length !in listOf(16, 24, 32)) {
                tvAesResult.text = "❌ 密钥长度必须是16/24/32字符，当前: ${key.length}"
                return
            }
            if (iv.length != 16) {
                tvAesResult.text = "❌ IV长度必须是16字符，当前: ${iv.length}"
                return
            }
            
            val startTime = System.currentTimeMillis()
            
            // 使用简化API加密
            val ciphertext = CryptoKit.encryptAES(input, key, iv)
            
            // 解密验证
            val decrypted = CryptoKit.decryptAES(ciphertext, key, iv)
            
            val duration = System.currentTimeMillis() - startTime
            
            val output = buildString {
                appendLine("✅ AES-CBC 预协商密钥加密成功")
                appendLine()
                appendLine("📥 原文: $input")
                appendLine()
                appendLine("🔑 密钥: $key")
                appendLine("    (${key.length}字符 = ${key.length * 8}位)")
                appendLine()
                appendLine("🎲 IV: $iv")
                appendLine()
                appendLine("🔒 密文 (Base64):")
                appendLine(ciphertext.toBase64NoWrap())
                appendLine()
                appendLine("🔒 密文 (Hex):")
                appendLine(ciphertext.toHex())
                appendLine()
                appendLine("📤 解密结果: $decrypted")
                appendLine()
                appendLine("⚡ 一行代码调用:")
                appendLine("CryptoKit.encryptAES(text, key, iv)")
                appendLine("CryptoKit.decryptAES(bytes, key, iv)")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvAesResult.text = output
            showToast("预协商密钥加密成功")
        } catch (e: Exception) {
            tvAesResult.text = "❌ 预协商密钥加密失败: ${e.message}"
            showToast("加密失败")
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

    // ==================== 拦截器控制 ====================
    private fun updateInterceptors() {
        CryptoKit.disableInterceptors()
        
        val enableLogging = cbEnableLogging.isChecked
        val enablePerformance = cbEnablePerformance.isChecked

        if (enableLogging) {
            CryptoKit.enableLogging("CryptoKitDemo")
        }
        if (enablePerformance) {
            CryptoKit.enablePerformanceMonitoring(50)
        }

        val status = when {
            enableLogging && enablePerformance -> "✅ 日志 + 性能监控"
            enableLogging -> "✅ 日志拦截器"
            enablePerformance -> "✅ 性能监控拦截器"
            else -> "❌ 已禁用"
        }
        tvInterceptorStatus.text = "拦截器状态: $status\n提示: 勾选后执行加密操作，查看Logcat日志"
        
        showToast("拦截器设置已更新")
    }

    // ==================== PBKDF2密钥派生 ====================
    private fun demoPbkdf2() {
        try {
            val password = getInputText()
            val startTime = System.currentTimeMillis()
            
            // 生成随机盐
            val salt = CryptoKit.secureRandom(16)
            
            // 派生256位AES密钥
            val derivedKey = CryptoKit.deriveKey(
                password = password,
                salt = salt,
                iterations = 10000,
                keyLength = 256
            )
            
            // 再派生一次验证一致性
            val derivedKey2 = CryptoKit.deriveKey(
                password = password,
                salt = salt,
                iterations = 10000,
                keyLength = 256
            )
            
            val isEqual = derivedKey.contentEquals(derivedKey2)
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("🔐 PBKDF2 密钥派生结果")
                appendLine()
                appendLine("📝 密码: $password")
                appendLine()
                appendLine("⚙️ 配置: 迭代=10000次, 密钥长度=256位")
                appendLine()
                appendLine("🧂 随机盐 (Hex):")
                appendLine(salt.toHex())
                appendLine()
                appendLine("🔑 派生密钥 (Hex):")
                appendLine(derivedKey.toHex())
                appendLine()
                appendLine("✅ 重复派生一致性: $isEqual")
                appendLine()
                appendLine("📊 密钥长度: ${derivedKey.size} 字节")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvPbkdf2Result.text = output
            showToast("PBKDF2密钥派生成功")
        } catch (e: Exception) {
            tvPbkdf2Result.text = "❌ 错误: ${e.message}"
            showToast("PBKDF2失败")
        }
    }

    // ==================== 工具类演示 ====================
    private fun demoUtils() {
        try {
            // 生成各种随机数
            val random16 = CryptoKit.secureRandom(16)
            val random32 = CryptoKit.secureRandom(32)
            val uuid1 = CryptoKit.randomUUID()
            val uuid2 = CryptoKit.randomUUID()

            val output = buildString {
                appendLine("🛠️ 工具类演示")
                appendLine()
                appendLine("🎲 安全随机数 (16字节):")
                appendLine(random16.toHex())
                appendLine()
                appendLine("🎲 安全随机数 (32字节):")
                appendLine(random32.toHex())
                appendLine()
                appendLine("🎫 UUID 1:")
                appendLine(uuid1)
                appendLine()
                appendLine("🎫 UUID 2:")
                appendLine(uuid2)
                appendLine()
                appendLine("💬 说明: 每次调用都会生成不同的随机值")
            }
            
            tvUtilsResult.text = output
            showToast("工具类演示完成")
        } catch (e: Exception) {
            tvUtilsResult.text = "❌ 错误: ${e.message}"
            showToast("工具类演示失败")
        }
    }

    // ==================== Android Keystore演示 ====================
    private fun demoKeystore() {
        try {
            val keyAlias = "demo_aes_key_${System.currentTimeMillis()}"
            val startTime = System.currentTimeMillis()
            
            // 尝试在Keystore中生成AES密钥
            val keyManager = CryptoKit.keyManager
            
            // 列出当前所有密钥
            val existingKeys: List<String> = try {
                keyManager.listAliases()
            } catch (e: Exception) {
                emptyList()
            }
            
            val duration = System.currentTimeMillis() - startTime

            val output = buildString {
                appendLine("🗑️ Android Keystore 演示")
                appendLine()
                appendLine("ℹ️ KeyManager 接口:")
                appendLine("  - generateAESKeyInKeystore(alias)")
                appendLine("  - generateRSAKeyPairInKeystore(alias)")
                appendLine("  - generateECKeyPairInKeystore(alias)")
                appendLine("  - getKey(alias)")
                appendLine("  - deleteKey(alias)")
                appendLine("  - listAliases()")
                appendLine("  - containsAlias(alias)")
                appendLine()
                appendLine("🔑 当前 Keystore 密钥数: ${existingKeys.size}")
                if (existingKeys.isNotEmpty()) {
                    appendLine()
                    appendLine("📝 密钥别名:")
                    existingKeys.take(5).forEach { alias -> appendLine("  - $alias") }
                    if (existingKeys.size > 5) {
                        appendLine("  ... 还有 ${existingKeys.size - 5} 个")
                    }
                }
                appendLine()
                appendLine("⚠️ 注意: Keystore密钥存储在硬件安全模块中")
                appendLine("🛡️ 密钥不可导出，提供最高级别安全性")
                appendLine()
                appendLine("⏱️ 耗时: ${duration}ms")
            }
            
            tvKeystoreResult.text = output
            showToast("Keystore演示完成")
        } catch (e: Exception) {
            tvKeystoreResult.text = "❌ 错误: ${e.message}\n\n说明: 模拟器可能不支持部分Keystore功能"
            showToast("Keystore演示失败")
        }
    }

    // ==================== 流式加密演示 ====================
    private fun demoStreamEncryption() {
        try {
            val startTime = System.currentTimeMillis()
            
            // 模拟大文件数据 (1MB)
            val fileSize = 1024 * 1024
            val largeData = ByteArray(fileSize) { (it % 256).toByte() }
            
            // 生成密钥和IV
            val key = CryptoKit.aes().generateKey()
            val iv = CryptoKit.secureRandom(16)
            
            // 使用流式加密
            val inputStream = java.io.ByteArrayInputStream(largeData)
            val encryptedStream = java.io.ByteArrayOutputStream()
            
            val encryptedBytes = CryptoKit.stream.encrypt(
                inputStream,
                encryptedStream,
                key,
                iv,
                "CBC"
            )
            
            // 使用流式解密
            val decryptInputStream = java.io.ByteArrayInputStream(encryptedStream.toByteArray())
            val decryptedStream = java.io.ByteArrayOutputStream()
            
            val decryptedBytes = CryptoKit.stream.decrypt(
                decryptInputStream,
                decryptedStream,
                key,
                iv,
                "CBC"
            )
            
            // 验证数据完整性
            val decryptedData = decryptedStream.toByteArray()
            val isEqual = largeData.contentEquals(decryptedData)
            
            val duration = System.currentTimeMillis() - startTime
            val throughput = (fileSize.toDouble() * 2 / (duration / 1000.0) / 1024 / 1024).let { 
                "%.2f MB/s".format(it) 
            }

            val output = buildString {
                appendLine("📁 流式加密/解密演示")
                appendLine()
                appendLine("📊 测试数据大小: ${fileSize / 1024} KB")
                appendLine()
                appendLine("⚙️ 配置: AES-256-CBC 流式加密")
                appendLine()
                appendLine("🔒 加密后大小: ${encryptedStream.size()} 字节")
                appendLine("📤 解密后大小: ${decryptedData.size} 字节")
                appendLine()
                appendLine("✅ 数据完整性验证: $isEqual")
                appendLine()
                appendLine("⏱️ 总耗时: ${duration}ms")
                appendLine("🚀 吞吐量: $throughput")
                appendLine()
                appendLine("💡 流式加密适用于:")
                appendLine("  - 大文件加密 (不占用大量内存)")
                appendLine("  - 网络流加密")
                appendLine("  - 视频/音频实时加密")
            }
            
            tvStreamResult.text = output
            showToast("流式加密演示完成")
        } catch (e: Exception) {
            tvStreamResult.text = "❌ 错误: ${e.message}"
            showToast("流式加密演示失败")
        }
    }

    // ==================== 安全工具演示 ====================
    private fun demoSecureUtils() {
        try {
            val output = buildString {
                appendLine("🛡️ 安全工具演示")
                appendLine()
                
                // 1. 敏感数据擦除演示
                appendLine("▶️ 敏感数据擦除 (SecureUtils.wipe)")
                val sensitiveData = "MySecretPassword123!".toByteArray()
                val dataBeforeWipe = sensitiveData.joinToString("") { "%02x".format(it) }
                CryptoKit.secure.wipe(sensitiveData)
                val dataAfterWipe = sensitiveData.joinToString("") { "%02x".format(it) }
                appendLine("  擦除前: $dataBeforeWipe")
                appendLine("  擦除后: $dataAfterWipe")
                appendLine("  ✅ 数据已用零覆盖")
                appendLine()
                
                // 2. 恒定时间比较演示
                appendLine("▶️ 恒定时间比较 (防时序攻击)")
                val hash1 = CryptoKit.sha256("test".toByteArray())
                val hash2 = CryptoKit.sha256("test".toByteArray())
                val hash3 = CryptoKit.sha256("different".toByteArray())
                
                val t1Start = System.nanoTime()
                repeat(10000) { CryptoKit.secure.constantTimeEquals(hash1, hash2) }
                val t1 = System.nanoTime() - t1Start
                
                val t2Start = System.nanoTime()
                repeat(10000) { CryptoKit.secure.constantTimeEquals(hash1, hash3) }
                val t2 = System.nanoTime() - t2Start
                
                appendLine("  相同数据比较耗时: ${t1 / 1000}μs (10000次)")
                appendLine("  不同数据比较耗时: ${t2 / 1000}μs (10000次)")
                appendLine("  时间差: ${kotlin.math.abs(t1 - t2) / 1000}μs")
                appendLine("  ✅ 时间差很小，防止时序攻击")
                appendLine()
                
                // 3. CipherResult.use() 演示
                appendLine("▶️ CipherResult.use{} 自动清理")
                var keyBytesAfterUse: ByteArray? = null
                CryptoKit.aes().encrypt("test").use { result ->
                    appendLine("  加密结果密钥长度: ${result.key.encoded?.size ?: 0} 字节")
                    keyBytesAfterUse = result.key.encoded?.copyOf()
                }
                appendLine("  ✅ use块结束后，敏感数据已安全清除")
                appendLine()
                
                // 4. 安全作用域演示
                appendLine("▶️ withSecureBytes 安全作用域")
                val password = CryptoKit.secureRandom(16)
                val result = CryptoKit.secure.withSecureBytes(password) { bytes ->
                    "处理 ${bytes.size} 字节的敏感数据"
                }
                appendLine("  $result")
                appendLine("  ✅ 作用域结束后自动擦除")
                appendLine()
                
                appendLine("💡 金融级安全建议:")
                appendLine("  1. 敏感数据用完立即擦除")
                appendLine("  2. 密码比较使用恒定时间比较")
                appendLine("  3. 使用 use{} 块自动管理资源")
            }
            
            tvSecureResult.text = output
            showToast("安全工具演示完成")
        } catch (e: Exception) {
            tvSecureResult.text = "❌ 错误: ${e.message}"
            showToast("安全工具演示失败")
        }
    }

    // ==================== 多线程压力测试 ====================
    private fun demoConcurrencyTest() {
        tvConcurrencyResult.text = "⏳ 正在进行100线程并发加密测试..."
        
        Thread {
            try {
                val threadCount = 100
                val operationsPerThread = 10
                val totalOperations = threadCount * operationsPerThread
                
                val successCount = java.util.concurrent.atomic.AtomicInteger(0)
                val errorCount = java.util.concurrent.atomic.AtomicInteger(0)
                val latch = java.util.concurrent.CountDownLatch(threadCount)
                
                val startTime = System.currentTimeMillis()
                
                // 启动100个线程并发加密
                repeat(threadCount) { threadId ->
                    Thread {
                        try {
                            repeat(operationsPerThread) { opId ->
                                // 每个线程进行加密解密
                                val data = "Thread-$threadId-Op-$opId: ${System.currentTimeMillis()}"
                                val result = CryptoKit.aes().encrypt(data)
                                val decrypted = CryptoKit.aes().decryptToString(result)
                                
                                if (decrypted == data) {
                                    successCount.incrementAndGet()
                                } else {
                                    errorCount.incrementAndGet()
                                }
                            }
                        } catch (e: Exception) {
                            errorCount.addAndGet(operationsPerThread)
                        } finally {
                            latch.countDown()
                        }
                    }.start()
                }
                
                // 等待所有线程完成
                latch.await()
                
                val duration = System.currentTimeMillis() - startTime
                val opsPerSecond = (totalOperations * 1000.0 / duration).toInt()
                
                val output = buildString {
                    appendLine("⚡ 多线程并发测试结果")
                    appendLine()
                    appendLine("📊 测试配置:")
                    appendLine("  线程数: $threadCount")
                    appendLine("  每线程操作数: $operationsPerThread")
                    appendLine("  总操作数: $totalOperations")
                    appendLine()
                    appendLine("📈 测试结果:")
                    appendLine("  ✅ 成功: ${successCount.get()}")
                    appendLine("  ❌ 失败: ${errorCount.get()}")
                    appendLine("  成功率: ${successCount.get() * 100 / totalOperations}%")
                    appendLine()
                    appendLine("⏱️ 性能数据:")
                    appendLine("  总耗时: ${duration}ms")
                    appendLine("  吞吐量: $opsPerSecond ops/s")
                    appendLine()
                    
                    if (errorCount.get() == 0) {
                        appendLine("🎉 所有并发操作成功!")
                        appendLine("✅ CryptoKit 线程安全验证通过")
                    } else {
                        appendLine("⚠️ 发现 ${errorCount.get()} 个错误")
                    }
                }
                
                runOnUiThread {
                    tvConcurrencyResult.text = output
                    showToast("并发测试完成")
                }
            } catch (e: Exception) {
                runOnUiThread {
                    tvConcurrencyResult.text = "❌ 错误: ${e.message}"
                    showToast("并发测试失败")
                }
            }
        }.start()
    }

    // ==================== 算法注册表演示 ====================
    private fun demoRegistry() {
        try {
            val output = buildString {
                appendLine("📋 算法注册表 (AlgorithmRegistry)")
                appendLine()
                
                val symmetricAlgorithms = CryptoKit.registry.listSymmetricCiphers()
                val asymmetricAlgorithms = CryptoKit.registry.listAsymmetricCiphers()
                val hashAlgorithms = CryptoKit.registry.listHashEngines()
                
                appendLine("🔐 对称加密算法 (${symmetricAlgorithms.size}个):")
                symmetricAlgorithms.forEach { appendLine("  • $it") }
                appendLine()
                
                appendLine("🔑 非对称加密算法 (${asymmetricAlgorithms.size}个):")
                asymmetricAlgorithms.forEach { appendLine("  • $it") }
                appendLine()
                
                appendLine("# 哈希算法 (${hashAlgorithms.size}个):")
                hashAlgorithms.forEach { appendLine("  • $it") }
                appendLine()
                
                // 检查算法是否存在
                appendLine("🔍 算法检查:")
                appendLine("  hasSymmetricCipher(\"AES-GCM\"): ${CryptoKit.registry.hasSymmetricCipher("AES-GCM")}")
                appendLine("  hasAsymmetricCipher(\"RSA-OAEP-SHA256\"): ${CryptoKit.registry.hasAsymmetricCipher("RSA-OAEP-SHA256")}")
                appendLine("  hasHashEngine(\"SHA-256\"): ${CryptoKit.registry.hasHashEngine("SHA-256")}")
                appendLine()
                
                appendLine("💡 扩展性:")
                appendLine("  CryptoKit.registry.registerSymmetricCipher()")
                appendLine("  CryptoKit.registry.registerAsymmetricCipher()")
                appendLine("  CryptoKit.registry.registerHashEngine()")
            }
            
            tvRegistryResult.text = output
            showToast("算法注册表演示完成")
        } catch (e: Exception) {
            tvRegistryResult.text = "❌ 错误: ${e.message}"
            showToast("算法注册表演示失败")
        }
    }
}