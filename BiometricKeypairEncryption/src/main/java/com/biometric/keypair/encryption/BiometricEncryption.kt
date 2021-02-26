package com.biometric.keypair.encryption

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import com.biometric.keypair.encryption.manager.CryptoResult
import com.biometric.keypair.encryption.manager.CryptographyManager
import com.biometric.keypair.encryption.manager.DecryptResult
import com.biometric.keypair.encryption.response.AuthResult
import com.biometric.keypair.encryption.response.BiometricStatus
import com.biometric.keypair.encryption.response.EncryptionCallBack
import com.biometric.keypair.encryption.response.EnrollResult
import com.biometric.keypair.encryption.utils.BiometricPromptUtils
import com.biometric.keypair.encryption.utils.BiometricSettings
import java.net.Authenticator
import java.nio.charset.Charset
import java.security.InvalidKeyException
import kotlin.properties.Delegates


//const val SHARED_PREFS_FILENAME = "biometric_prefs"
//const val CIPHERTEXT_WRAPPER = "ciphertext_wrapper"

//private const val ANDROID_KEY_STORE = "AndroidKeyStore"


class BiometricEncryption private constructor(
    private val context: Context,
    private val settings: BiometricSettings,
    private val SHARED_PREFS_FILENAME : String = "biometric_prefs",
    private val CIPHERTEXT_WRAPPER :String = "ciphertext_wrapper"
) : BioManager {

    private lateinit var _keyStoreName: String
    private lateinit var _algo: String
    private var _keysize by Delegates.notNull<Int>()
    private lateinit var _padding: String
    private lateinit var _blockMode: String

    private val cryptographyManager by lazy { CryptographyManager(_keyStoreName, _algo, _keysize, _padding, _blockMode) }
//    private val promptInfo: BiometricPrompt.PromptInfo? = BiometricPromptUtils

//        BiometricPromptUtils.createPromptInfo()

//    private val keyGenerator by lazy { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")}

//    private val fingerprintManager by lazy { FingerprintManagerCompat.from(context) }
//    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEY_STORE) }
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
        // Default is WEAK
        return when(BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)){
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

    @RequiresApi(Build.VERSION_CODES.M)
    override fun enrollAndEncrypt(activity: AppCompatActivity, plainText: String, biometricUtils: BiometricPromptUtils?): EnrollResult {
        return try {
            Log.d("Andreas", "enroll")
//            createKeyPair()
//            Log.d("Andreas", "createKeyPair")

                when (val cipherResult =
                    cryptographyManager.getInitializedCipherForEncryption()) {
                    is CryptoResult.Result -> {
                        val cipher = cipherResult.cipher

                        if (_algo == KeyProperties.KEY_ALGORITHM_RSA) {

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
                            EnrollResult.Result(encryptedServerTokenWrapper.ciphertext.toBase64Str())
                        } else if (_algo == KeyProperties.KEY_ALGORITHM_AES){
                            val promptInfo = biometricUtils?.createPromptInfo()
                            val biometricPrompt =
                                biometricUtils?.createBiometricPrompt(
                                    activity,
                                    encryptAndStoreServerTokenEdit(plainText)
                                )
                                    ?: throw error("Prompt Info error")
                            biometricPrompt.authenticate(
                                promptInfo!!,
                                BiometricPrompt.CryptoObject(cipher)
                            )
                            EnrollResult.Pending
                        } else {
                            EnrollResult.Error("Error 2", null)
                        }
                    }
                    is CryptoResult.Error -> {

                        Log.d("Andreas", "enroll - $cipherResult")
                        EnrollResult.Error("Error create cipher encryption", cipherResult.error)
                    }
                }
//            EnrollResult.Error("Error 1", null)
        } catch (e: InvalidKeyException) {
            EnrollResult.Error(e.toString(), e)
        }
    }

    private fun encryptAndStoreServerTokenEdit (plainText: String) : (BiometricPrompt.AuthenticationResult) -> EncryptionCallBack {
        return {
            Log.d("Andreas", "encryptAndStoreServerToken")
            it.cryptoObject?.let {
                it.cipher?.let {
                    Log.d("Andreas", "cryptoObject")
                    val encryptedServerTokenWrapper = cryptographyManager.encryptData(plainText, it)
                    cryptographyManager.persistCiphertextWrapperToSharedPrefs(
                        encryptedServerTokenWrapper,
                        context,
                        SHARED_PREFS_FILENAME,
                        Context.MODE_PRIVATE,
                        CIPHERTEXT_WRAPPER
                    )
                    enableFingerPrint(BiometricSettings.BiometricFuncStatus.Enabled)

                    val message = String(
                        encryptedServerTokenWrapper.ciphertext,
                        Charset.forName("UTF-8")
                    )

                    EncryptionCallBack.Result(encryptedServerTokenWrapper.ciphertext.toBase64Str())
                }?:EncryptionCallBack.Error("Oke")
            } ?: EncryptionCallBack.Error("Oke2")
//           EncryptionCallBack.Error("asdf")
        }
    }



    override fun authAndDecrypt(activity: AppCompatActivity, biometricUtils: BiometricPromptUtils) : AuthResult {
        return try {
            ciphertextWrapper?.let { textWrapper ->
                val cipherResult = cryptographyManager.getInitializedCipherForDecryption(
                    textWrapper.initializationVector
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


        }catch (e: Exception){
            AuthResult.Error("Error unknown", e)
        }
    }

    private fun decryptAfterAuthen(authResult: BiometricPrompt.AuthenticationResult): EncryptionCallBack {
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
                                return EncryptionCallBack.Error("BiometricKeyChanged")
                            }
                            is DecryptResult.Result -> {
                                val plaintext = response.decrypted
                                //                        DataCache.token = plaintext
                                Log.d("Andreas", "Token " + plaintext)
                                Toast.makeText(context, "Success decrypt $plaintext", Toast.LENGTH_LONG)
                                    .show()

                                return EncryptionCallBack.Result(plaintext)
                            }
                            else -> {
                                return EncryptionCallBack.Error("Other Error")

                                //                        callBackParam.Failed(BiometricStatus.ERROR_UNKNOWN)
                            }
                        }
                    }

                } ?: return EncryptionCallBack.Error("cipher null") //Log.d("Andreas", "ciphertextWrapper Empty")
            EncryptionCallBack.Error("Some Object Null")
        }catch (ex: Exception){
            EncryptionCallBack.Error(ex.toString())
        }
    }

    override fun isSupportedSDK(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
    }

    class Builder( private val context: Context, private val settings: BiometricSettings){
        private var keyStoreName = "bioAuthEncryptionTest123"
        private var algorithm = KeyProperties.KEY_ALGORITHM_AES
        private var keysize = 256
        private var encryptionPadding = KeyProperties.ENCRYPTION_PADDING_NONE
        private var encryptionBlockMode = KeyProperties.BLOCK_MODE_GCM
        private lateinit var prefName : String
        private lateinit var cipherWrapper : String

//        private var algorithm = KeyProperties.KEY_ALGORITHM_RSA
//        private var keysize = 256
//        private var encryptionPadding = KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
//        private var encryptionBlockMode = KeyProperties.BLOCK_MODE_ECB

        fun withRSASettings(): Builder{
            keyStoreName = "bioAuthEncryptionRSA"
            algorithm = KeyProperties.KEY_ALGORITHM_RSA
            keysize = 0
            encryptionPadding = KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
            encryptionBlockMode = KeyProperties.BLOCK_MODE_ECB
            return this
        }

        fun withAESSEttings(): Builder{
            keyStoreName = "bioAuthEncryptionAES"
            algorithm = KeyProperties.KEY_ALGORITHM_AES
            keysize = 256
            encryptionPadding = KeyProperties.ENCRYPTION_PADDING_NONE
            encryptionBlockMode = KeyProperties.BLOCK_MODE_GCM
            return this
        }

        fun configuration(prefName : String, cipherWrapper: String) : Builder{
            this.prefName = prefName
            this.cipherWrapper = cipherWrapper
            return this
        }
//
//        fun withKeyStoreName(name: String): Builder{
//            keyStoreName = name
//            return this
//        }
//
//        fun withAlgorithm(name: String): Builder{
//            algorithm = name
//            return this
//        }
//
//        fun withKeySize(size: Int): Builder{
//            keysize = size
//            return this
//        }
//
//        fun withEncryptionPadding(name: String): Builder{
//            encryptionPadding = name
//            return this
//        }
//
//        fun withEncryptionBlockMode(name: String): Builder{
//            encryptionBlockMode = name
//            return this
//        }

        fun build() = (if (prefName==null) BiometricEncryption(context, settings) else BiometricEncryption(context, settings, prefName, cipherWrapper) ).apply {
            this._keyStoreName = keyStoreName
            this._algo = algorithm
            this._keysize = keysize
            this._padding = encryptionPadding
            this._blockMode = encryptionBlockMode
        }
    }
}

private fun ByteArray.encodeBase64(): ByteArray = Base64.encode(this, Base64.DEFAULT)
private fun ByteArray.toBase64Str(): String = String(Base64.encode(this, Base64.DEFAULT))