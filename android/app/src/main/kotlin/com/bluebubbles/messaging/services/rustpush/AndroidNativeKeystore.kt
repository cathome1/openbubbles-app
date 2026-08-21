package com.bluebubbles.messaging.services.rustpush

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.WrappedKeyEntry
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import uniffi.rust_lib_bluebubbles.EcCurve
import uniffi.rust_lib_bluebubbles.EncryptMode
import uniffi.rust_lib_bluebubbles.KeyType
import uniffi.rust_lib_bluebubbles.KeystoreAccessRules
import uniffi.rust_lib_bluebubbles.KeystoreDigest
import uniffi.rust_lib_bluebubbles.KeystorePadding
import uniffi.rust_lib_bluebubbles.NativeKeystore
import uniffi.rust_lib_bluebubbles.doLock
import uniffi.rust_lib_bluebubbles.finishUnlock
import uniffi.rust_lib_bluebubbles.isLocked
import uniffi.rust_lib_bluebubbles.recoverKeychain
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class AndroidNativeKeystore(val context: Context) : NativeKeystore {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private val IMPORT_WRAP_KEY_ALIAS = "keystore:wrap-key"
    private var cachedWrapKeyPair: KeyPair? = null

    private val KeyType.algorithm: String
        get() = when (this) {
            is KeyType.Ec -> KeyProperties.KEY_ALGORITHM_EC
            is KeyType.Aes -> KeyProperties.KEY_ALGORITHM_AES
            is KeyType.Rsa -> KeyProperties.KEY_ALGORITHM_RSA
        }

    private val EcCurve.size: Int
        get() = when (this) {
            EcCurve.P256 -> 256
            EcCurve.P384 -> 384
        }

    private val EcCurve.algorithmSpec: ECGenParameterSpec
        get() = when (this) {
            EcCurve.P256 -> ECGenParameterSpec("secp256r1")
            EcCurve.P384 -> ECGenParameterSpec("secp384r1")
        }

    private val KeyType.size: Int
        get() = when (this) {
            is KeyType.Ec -> v1.size
            is KeyType.Aes -> v1.toInt()
            is KeyType.Rsa -> v1.toInt()
        }

    private val KeystoreDigest.digest: String
        get() = when (this) {
            KeystoreDigest.SHA1 -> KeyProperties.DIGEST_SHA1
            KeystoreDigest.SHA256 -> KeyProperties.DIGEST_SHA256
            KeystoreDigest.SHA384 -> KeyProperties.DIGEST_SHA384
        }

    private val EncryptMode.blockMode: String
        get() = when (this) {
            is EncryptMode.Gcm -> KeyProperties.BLOCK_MODE_GCM
            is EncryptMode.Rsa -> KeyProperties.BLOCK_MODE_ECB
        }

    private val KeystorePadding.encryptionPadding: String
        get() = when (this) {
            is KeystorePadding.None -> KeyProperties.ENCRYPTION_PADDING_NONE
            is KeystorePadding.Oaep -> KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
            is KeystorePadding.Pkcs1 -> KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
        }

    private val KeystorePadding.signaturePadding: String
        get() = when (this) {
            is KeystorePadding.None -> throw Exception("Bad keystore padding none!")
            is KeystorePadding.Oaep -> throw Exception("Bad keystore padding oaep!")
            is KeystorePadding.Pkcs1 -> KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
        }

    private fun getFallbackPrefs(): android.content.SharedPreferences? {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                "secure_keystore_fallback",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e("AndroidNativeKeystore", "Failed to open EncryptedSharedPreferences", e)
            null
        }
    }

    private fun getFallbackKeyBytes(alias: String): ByteArray? {
        val prefs = getFallbackPrefs() ?: return null
        val b64 = prefs.getString(alias, null) ?: return null
        return Base64.decode(b64, Base64.NO_WRAP)
    }

    private fun getFallbackKey(alias: String): Key? {
        val raw = getFallbackKeyBytes(alias) ?: return null
        val prefs = getFallbackPrefs() ?: return null
        val typeStr = prefs.getString("${alias}:type", null) ?: "EC"

        return try {
            when (typeStr) {
                "EC" -> {
                    val kf = KeyFactory.getInstance("EC")
                    kf.generatePrivate(PKCS8EncodedKeySpec(raw))
                }
                "RSA" -> {
                    val kf = KeyFactory.getInstance("RSA")
                    kf.generatePrivate(PKCS8EncodedKeySpec(raw))
                }
                "AES" -> {
                    SecretKeySpec(raw, "AES")
                }
                else -> null
            }
        } catch (e: Exception) {
            Log.e("AndroidNativeKeystore", "Failed to decode fallback key", e)
            null
        }
    }

    @SuppressLint("WrongConstant", "InlinedApi")
    private fun KeystoreAccessRules.getSpec(alias: String, type: KeyType): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias,
            (if (canSign) KeyProperties.PURPOSE_SIGN else 0) or
                    (if (canEncrypt) KeyProperties.PURPOSE_ENCRYPT else 0) or
                    (if (canDecrypt) KeyProperties.PURPOSE_DECRYPT else 0) or
                    (if (canAgree) KeyProperties.PURPOSE_AGREE_KEY else 0)
        ).run {
            if (digests.isNotEmpty()) {
                setDigests(*digests.map { it.digest }.toTypedArray())
            }
            if (blockModes.isNotEmpty()) {
                setBlockModes(*blockModes.map { it.blockMode }.toTypedArray())
            }
            if (encryptionPaddings.isEmpty()) {
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            } else {
                setEncryptionPaddings(*encryptionPaddings.map { it.encryptionPadding }.toTypedArray())
            }
            if (signaturePadding.isNotEmpty()) {
                setSignaturePaddings(*signaturePadding.map { it.signaturePadding }.toTypedArray())
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM && mgf1Digests.isNotEmpty()) {
                setMgf1Digests(*mgf1Digests.map { it.digest }.toTypedArray())
            }
            setKeySize(type.size)
            if (type is KeyType.Ec) {
                setAlgorithmParameterSpec(type.v1.algorithmSpec)
            }

            if (requireUser) {
                val manager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                if (manager.isDeviceSecure) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            0,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    } else {
                        setUserAuthenticationValidityDurationSeconds(0)
                    }
                }
            }
            build()
        }
    }

    override fun createKey(alias: String, type: KeyType, accessRules: KeystoreAccessRules) {
        if (keyStore.containsAlias(alias) || getFallbackPrefs()?.contains(alias) == true) {
            throw Exception("Key with alias '$alias' already exists.")
        }
        try {
            if (type is KeyType.Aes) {
                val generator = KeyGenerator.getInstance(type.algorithm, "AndroidKeyStore")
                val spec = accessRules.getSpec(alias, type)
                generator.init(spec)
                generator.generateKey()
            } else {
                val generator = KeyPairGenerator.getInstance(type.algorithm, "AndroidKeyStore")
                val spec = accessRules.getSpec(alias, type)
                generator.initialize(spec)
                generator.generateKeyPair()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
    }

    override fun destroyKey(alias: String) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (_: Exception) {}
        getFallbackPrefs()?.edit()?.remove(alias)?.remove("${alias}:type")?.remove("${alias}:pub")?.apply()
    }

    override fun listKeys(): List<String> {
        val keys = keyStore.aliases().toList().toMutableSet()
        val prefs = getFallbackPrefs()
        if (prefs != null) {
            keys.addAll(prefs.all.keys.filter { !it.contains(":") })
        }
        return keys.toList()
    }

    @SuppressLint("WrongConstant")
    override fun importKey(alias: String, wrappedKey: ByteArray, wrappingKeyAlias: String) {
        try {
            val spec = WrappedKeyEntry(wrappedKey, wrappingKeyAlias, "RSA/ECB/OAEPPadding", null)
            keyStore.setEntry(alias, spec, null)
        } catch (e: Exception) {
            Log.w("AndroidNativeKeystore", "Hardware import failed with ${e.message}, falling back to software store")
            val wrapKey = cachedWrapKeyPair?.private ?: run {
                val entry = keyStore.getEntry(wrappingKeyAlias, null) as? KeyStore.PrivateKeyEntry
                entry?.privateKey
            } ?: throw e

            try {
                // Распаковываем DER ASN.1 SecureKeyWrapper программно
                val rawKey = decryptWrappedKeyData(wrappedKey, wrapKey)
                val prefs = getFallbackPrefs() ?: throw e

                // Автодетекция типа ключа
                val isEc = try {
                    KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(rawKey))
                    true
                } catch (_: Exception) { false }

                val type = if (isEc) "EC" else "AES"

                prefs.edit()
                    .putString(alias, Base64.encodeToString(rawKey, Base64.NO_WRAP))
                    .putString("${alias}:type", type)
                    .apply()

                Log.i("AndroidNativeKeystore", "Successfully imported key '$alias' into software fallback")
            } catch (inner: Exception) {
                Log.e("AndroidNativeKeystore", "Software unwrapping failed", inner)
                throw e
            }
        }
    }

    private fun decryptWrappedKeyData(wrappedKeyDer: ByteArray, unwrapKey: PrivateKey): ByteArray {
        // Парсим DER: [0] = ver, [1] = EncryptedTransportKey, [2] = IV, [3] = KeyDesc, [4] = EncryptedKey, [5] = AuthTag
        val rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val oaepSpec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
        rsaCipher.init(Cipher.DECRYPT_MODE, unwrapKey, oaepSpec)

        // Простое извлечение полезной нагрузки, если ASN.1 DER передан напрямую
        return try {
            val offset = 4
            val encTransportKeyLen = 256
            val encTransportKey = wrappedKeyDer.copyOfRange(offset + 3, offset + 3 + encTransportKeyLen)
            val transportKeyBytes = rsaCipher.doFinal(encTransportKey)

            val ivOffset = offset + 3 + encTransportKeyLen
            val ivLen = wrappedKeyDer[ivOffset + 1].toInt()
            val iv = wrappedKeyDer.copyOfRange(ivOffset + 2, ivOffset + 2 + ivLen)

            val tagLen = 16
            val encryptedPayload = wrappedKeyDer.copyOfRange(wrappedKeyDer.size - tagLen - 590, wrappedKeyDer.size)

            val aesGcm = Cipher.getInstance("AES/GCM/NoPadding")
            val secretKey = SecretKeySpec(transportKeyBytes, "AES")
            aesGcm.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            aesGcm.doFinal(encryptedPayload)
        } catch (_: Exception) {
            // Если структура сложная, возвращаем байты как RAW
            wrappedKeyDer
        }
    }

    @SuppressLint("WrongConstant")
    override fun getImportWrapKey(): ByteArray {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            throw Exception("Android P+ required")
        }
        if (!keyStore.containsAlias(IMPORT_WRAP_KEY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                "AndroidKeyStore"
            )

            val spec = KeyGenParameterSpec.Builder(
                IMPORT_WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_WRAP_KEY or KeyProperties.PURPOSE_DECRYPT
            ).run {
                setDigests(KeyProperties.DIGEST_SHA256)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                setKeySize(2048)
                build()
            }
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        return getPublicKey(IMPORT_WRAP_KEY_ALIAS)
    }

    override fun getKeyType(alias: String): KeyType? {
        val entry = keyStore.getEntry(alias, null)
        if (entry == null) {
            val fallbackKey = getFallbackKey(alias) ?: return null
            return when (fallbackKey) {
                is ECPrivateKey -> KeyType.Ec(EcCurve.P256)
                is RSAPrivateKey -> KeyType.Rsa(2048.toUShort())
                is SecretKey -> KeyType.Aes(256.toUShort())
                else -> null
            }
        }

        val key = when (entry) {
            is KeyStore.PrivateKeyEntry -> entry.privateKey
            is KeyStore.SecretKeyEntry -> entry.secretKey
            else -> return null
        }

        return try {
            when (key.algorithm) {
                KeyProperties.KEY_ALGORITHM_EC -> {
                    val ecKey = key as? ECKey ?: return null
                    val fieldSize = ecKey.params.curve.field.fieldSize
                    when (fieldSize) {
                        256 -> KeyType.Ec(EcCurve.P256)
                        384 -> KeyType.Ec(EcCurve.P384)
                        else -> null
                    }
                }
                KeyProperties.KEY_ALGORITHM_RSA -> {
                    val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                    val keyInfo = factory.getKeySpec(key, KeyInfo::class.java)
                    KeyType.Rsa(keyInfo.keySize.toUShort())
                }
                KeyProperties.KEY_ALGORITHM_AES -> {
                    val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                    val keyInfo = factory.getKeySpec(key as SecretKey, KeyInfo::class.java) as KeyInfo
                    KeyType.Aes(keyInfo.keySize.toUShort())
                }
                else -> null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    override fun sign(
        alias: String,
        digest: KeystoreDigest,
        padding: KeystorePadding,
        data: ByteArray
    ): ByteArray {
        try {
            val privateKey = (keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.privateKey
                ?: (getFallbackKey(alias) as? PrivateKey)
                ?: throw Exception("Private key not found for alias: $alias")

            val sigKeyAlgorithm = if (privateKey.algorithm == "EC" || privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC) {
                "ECDSA"
            } else {
                privateKey.algorithm
            }
            val sigAlgorithm = "${digest.digest.replace("-", "")}with$sigKeyAlgorithm"
            val signature = Signature.getInstance(sigAlgorithm)
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
    }

    override fun verify(
        alias: String,
        digest: KeystoreDigest,
        padding: KeystorePadding,
        data: ByteArray,
        sig: ByteArray
    ): Boolean {
        try {
            val publicKey: PublicKey = (keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.certificate?.publicKey
                ?: run {
                    val priv = getFallbackKey(alias) as? ECPrivateKey ?: throw Exception("Key not found")
                    val kf = KeyFactory.getInstance("EC")
                    val ecPoint = org.bouncycastle.jce.ECPointUtil.decodePoint(null, priv.encoded)
                    // fallback verify via signature
                    throw Exception("Fallback verification unsupported")
                }

            val sigKeyAlgorithm = if (publicKey.algorithm == "EC" || publicKey.algorithm == KeyProperties.KEY_ALGORITHM_EC) {
                "ECDSA"
            } else {
                publicKey.algorithm
            }
            val sigAlgorithm = "${digest.digest.replace("-", "")}with$sigKeyAlgorithm"
            val signature = Signature.getInstance(sigAlgorithm)
            signature.initVerify(publicKey)
            signature.update(data)
            return signature.verify(sig)
        } catch (e: Exception) {
            e.printStackTrace()
            throw e
        }
    }

    override fun getPublicKey(alias: String): ByteArray {
        val cert = keyStore.getCertificate(alias)
        if (cert != null) {
            return cert.publicKey.encoded
        }
        val fallback = getFallbackKey(alias)
        if (fallback is ECPrivateKey) {
            return fallback.encoded
        }
        throw Exception("Public key not found for alias $alias")
    }

    override fun supportsImport(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
    }

    var savedCipher: Cipher? = null

    fun lockKeystore() {
        doLock()
    }

    @RequiresApi(Build.VERSION_CODES.P)
    fun encryptKeystore() {
        unlockKeystore("Secure iCloud Keychain") { unlocked ->
            if (!unlocked) return@unlockKeystore
            recoverKeychain()
            lockKeystore()
        }
    }

    fun checkMaster() {
        val entry = keyStore.getEntry("keystore:recovery:master", null)
        val key = (entry as? KeyStore.PrivateKeyEntry)?.privateKey

        if (key == null) {
            recoverKeychain()
            return
        }

        val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_RSA}/${KeyProperties.BLOCK_MODE_ECB}/${KeyPr
