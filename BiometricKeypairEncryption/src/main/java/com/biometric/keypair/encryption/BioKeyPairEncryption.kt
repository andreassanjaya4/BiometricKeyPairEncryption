package com.biometric.keypair.encryption

import android.Manifest
import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import com.biometric.keypair.encryption.manager.CryptoResult
import com.biometric.keypair.encryption.manager.CryptographyManager
import com.biometric.keypair.encryption.manager.DecryptResult
import com.biometric.keypair.encryption.response.AuthResult
import com.biometric.keypair.encryption.response.BiometricStatus
import com.biometric.keypair.encryption.response.DecryptCallBack
import com.biometric.keypair.encryption.response.EnrollResult
import com.biometric.keypair.encryption.utils.BiometricPromptUtils
import com.biometric.keypair.encryption.utils.BiometricSettings
import java.security.*


const val SHARED_PREFS_FILENAME = "biometric_prefs"
const val CIPHERTEXT_WRAPPER = "ciphertext_wrapper"

private const val ANDROID_KEY_STORE = "AndroidKeyStore"


class BioKeyPairEncryption (
    private val context: Context,
    private val settings: BiometricSettings
) : BioManager {

    private val cryptographyManager = CryptographyManager()
    private lateinit var _keyStoreName: String

    private val keyGenerator by lazy { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")}

//    private val fingerprintManager by lazy { FingerprintManagerCompat.from(context) }
    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEY_STORE) }
//    private var cancellationSignal: CancellationSignal? = null
//    private var selfCancelled: Boolean = false

    private val ciphertextWrapper
        get() = cryptographyManager.getCiphertextWrapperFromSharedPrefs(
            context,
            SHARED_PREFS_FILENAME,
            Context.MODE_PRIVATE,
            CIPHERTEXT_WRAPPER
        )

    override fun checkBiometric() : BiometricStatus {
        return when(BiometricManager.from(context).canAuthenticate()){
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricStatus.ERROR_NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.ERROR_NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.ERROR_NONE_ENROLLED
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.SUCCESS
            else -> BiometricStatus.ERROR_UNKNOWN
        }
    }

    override fun isFingerEnabled() = when(val bioStatus = checkBiometric()){
        BiometricStatus.SUCCESS -> { settings.isEnabled() }
        else -> { BiometricSettings.BiometricFuncStatus.Unknown }
    }

    override fun enableFingerPrint(status: BiometricSettings.BiometricFuncStatus) {
        settings.setBiometricStatus(status)
    }

    /**
     * Generates an asymmetric key pair in the Android Keystore. Every use of the private key must
     * be authorized by the user authenticating with fingerprint. Public key use is unrestricted.
     */
    @TargetApi(Build.VERSION_CODES.M)
    private fun createKeyPair(): Boolean {

        try {
            keyStore.load(null)
            keyGenerator.initialize(
                KeyGenParameterSpec.Builder(_keyStoreName,
                    KeyProperties.PURPOSE_DECRYPT)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    // Require the user to authenticate with a fingerprint to authorize
                    // every use of the private key
                    .setUserAuthenticationRequired(true)
                    .build())
            keyGenerator.generateKeyPair()
            return true
        } catch (e: InvalidAlgorithmParameterException) {
            return false
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun enrollAndEncrypt(activity: AppCompatActivity, plainText: String): EnrollResult {
        return try {
            Log.d("Andreas", "enroll")
            createKeyPair()
            Log.d("Andreas", "createKeyPair")
            when (val publicKeyResult = getPublicKey()){
                is PublicKeyResult.Result -> {
                    when (val cipherResult =
                        cryptographyManager.getInitializedCipherForEncryption(publicKeyResult.publicKey)) {
                        is CryptoResult.Result -> {
                            val cipher = cipherResult.cipher
                            val encryptedServerTokenWrapper =
                                cryptographyManager.encryptData(plainText, cipher)
                            cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                                encryptedServerTokenWrapper,
                                context,
                                SHARED_PREFS_FILENAME,
                                Context.MODE_PRIVATE,
                                CIPHERTEXT_WRAPPER
                            )
                            enableFingerPrint(BiometricSettings.BiometricFuncStatus.Enabled)
                            EnrollResult.Result
                        }
                        else -> {
                            Log.d("Andreas", "enroll - $cipherResult")
                            EnrollResult.Error("Error create cipher encryption", null)
                        }
                    }
                }
                is PublicKeyResult.Error -> {
                    EnrollResult.Error("Error Get Publickey", publicKeyResult.error)
                }
            }
        } catch (e: InvalidKeyException) {
            EnrollResult.Error(e.toString(), e)
        }
    }

    override fun authAndDecrypt(activity: AppCompatActivity, biometricUtils: BiometricPromptUtils) : AuthResult {
        return try {
            when (val privateKeyResult = getPrivateKey()) {
                is PrivateKeyResult.Result -> {
                    ciphertextWrapper?.let { textWrapper ->
                        val cipherResult = cryptographyManager.getInitializedCipherForDecryption(
                            textWrapper.initializationVector, privateKeyResult.key
                        )
                        when (cipherResult) {
                            is CryptoResult.Result -> {
                                val cipher = cipherResult.cipher
                                val promptInfo = biometricUtils.createPromptInfo()
                                val biometricPrompt =
                                    biometricUtils.createBiometricPrompt(
                                        activity,
                                        ::decryptAfterAuthen
                                    )
                                biometricPrompt.authenticate(
                                    promptInfo!!,
                                    BiometricPrompt.CryptoObject(cipher)
                                )
                                AuthResult.Result
                            }
                            is CryptoResult.Error -> {
                                AuthResult.Error("Crypto Error", cipherResult.error)
                            }
                        }
                    } ?: AuthResult.Error("cipher missing", null)
                }
                is PrivateKeyResult.Error -> {
                    AuthResult.Error("Get PrivateKey Error", privateKeyResult.error)
                }
            }
        }catch (e: Exception){
            AuthResult.Error("Error unknown", e)
        }
    }

    private fun decryptAfterAuthen(authResult: BiometricPrompt.AuthenticationResult): DecryptCallBack {
        Log.d("Andreas", "decryptServerTokenFromStorage")
        return try {
                ciphertextWrapper?.let { textWrapper ->
                    authResult.cryptoObject?.cipher?.let {
                        when (val response = cryptographyManager.decryptData(textWrapper.ciphertext, it)) {
                            DecryptResult.BiometricKeyChanged -> {
                                //                        callBackParam.Failed(BiometricStatus.ERROR_KEY_CHANGED)
                                Log.d("Andreas", "Errror 1")
                                Toast.makeText(
                                    context,
                                    "Fingerprint changed, please enroll again",
                                    Toast.LENGTH_LONG
                                ).show()
                                return DecryptCallBack.Error("BiometricKeyChanged")
                            }
                            is DecryptResult.Result -> {
                                val plaintext = response.decrypted
                                //                        DataCache.token = plaintext
                                Log.d("Andreas", "Token " + plaintext)
                                Toast.makeText(context, "Success decrypt $plaintext", Toast.LENGTH_LONG)
                                    .show()

                                return DecryptCallBack.Result(plaintext)
                            }
                            else -> {
                                return DecryptCallBack.Error("Other Error")

                                //                        callBackParam.Failed(BiometricStatus.ERROR_UNKNOWN)
                            }
                        }
                    }

                } ?: return DecryptCallBack.Error("cipher null") //Log.d("Andreas", "ciphertextWrapper Empty")
            DecryptCallBack.Error("Some Object Null")
        }catch (ex: Exception){
            DecryptCallBack.Error(ex.toString())
        }
    }

    private fun getPublicKey(): PublicKeyResult {
        var publicKey: PublicKey? = null
        return try {
            keyStore.load(null)
            publicKey = keyStore.getCertificate(_keyStoreName).publicKey
            PublicKeyResult.Result(publicKey)
        } catch (e: Exception) {
            Log.d("Andreas", "Error ${e.toString()}")
            PublicKeyResult.Error(e)
        }
    }

    private fun getPrivateKey(): PrivateKeyResult {
        var privateKey: PrivateKey? = null
        return try {
            keyStore.load(null)
            privateKey = keyStore.getKey(_keyStoreName, null) as PrivateKey

            PrivateKeyResult.Result(privateKey)
        } catch (e: Exception) {
            PrivateKeyResult.Error(e)
        }
    }

    override fun isSupportedSDK(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }

//    override fun checkSelfPermission(): Boolean {
//        return ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED
//    }

//    override fun resetAll(){
//        enableFingerPrint(status = BioAuthSettings.BiometricStatus.Unknown)
//    }

    sealed class PublicKeyResult{
        class Error(val error: Exception?): PublicKeyResult()
        class Result(val publicKey: PublicKey): PublicKeyResult()
    }
    sealed class PrivateKeyResult{
        class Error(val error: Exception?): PrivateKeyResult()
        class Result(val key: PrivateKey): PrivateKeyResult()
    }


    class Builder( private val context: Context, private val settings: BiometricSettings){
        private var keyStoreName = "bioAuthEncryption"

        fun withKeyStoreName(name: String): Builder{
            keyStoreName = name
            return this
        }

        fun build() = BioKeyPairEncryption(context, settings).apply {
            this._keyStoreName = keyStoreName
        }
    }
}

private fun ByteArray.encodeBase64(): ByteArray = Base64.encode(this, Base64.DEFAULT)
