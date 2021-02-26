package com.biometric.keypair.encryption.manager

import android.annotation.SuppressLint
import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import java.nio.charset.Charset
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

const val ANDROID_KEYSTORE = "AndroidKeyStore"
/**
 * Handles encryption and decryption
 */
interface CryptographyManager {

    fun getInitializedCipherForEncryption(): CryptoResult

    fun getInitializedCipherForDecryption(initializationVector: ByteArray): CryptoResult

    /**
     * The Cipher created with [getInitializedCipherForEncryption] is used here
     */
    fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper

    /**
     * The Cipher created with [getInitializedCipherForDecryption] is used here
     */
    fun decryptData(ciphertext: ByteArray, cipher: Cipher): DecryptResult

    fun removeBiometric(plaintext: String)

    fun persistCiphertextWrapperToSharedPrefs(
        ciphertextWrapper: CiphertextWrapper,
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    )

    fun clearCiphertextWrapperToSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    )

    fun getCiphertextWrapperFromSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ): CiphertextWrapper?

}

sealed class CryptoResult{
    class Error(val error: java.lang.Exception?): CryptoResult()
    class Result(val cipher: Cipher): CryptoResult()
}

sealed class DecryptResult {
    object BiometricKeyChanged: DecryptResult()
    object Error: DecryptResult()
    class Result(val decrypted: String): DecryptResult()
}

fun CryptographyManager(keyName: String,
                        KEY_ALGORITHM: String,
                        KEY_SIZE: Int?,
                        ENCRYPTION_PADDING: String,
                        ENCRYPTION_BLOCK_MODE: String?): CryptographyManager = CryptographyManagerImpl(keyName, KEY_ALGORITHM, KEY_SIZE, ENCRYPTION_PADDING, ENCRYPTION_BLOCK_MODE)

/**
 * To get an instance of this private CryptographyManagerImpl class, use the top-level function
 * fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()
 */

private class CryptographyManagerImpl (
    private val keyName: String,
    private val KEY_ALGORITHM: String,
    private val KEY_SIZE: Int?,
    private val ENCRYPTION_PADDING: String,
    private val ENCRYPTION_BLOCK_MODE: String?) : CryptographyManager  {

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(ANDROID_KEYSTORE) }

    override fun getInitializedCipherForEncryption(): CryptoResult {
        return try{
            val cipher = getCipher()
            Log.d("Andreass", "getInitializedCipherForEncryption $KEY_ALGORITHM")
            if (KEY_ALGORITHM == KeyProperties.KEY_ALGORITHM_AES){
                val secretKey = getOrCreateSecretKey()?.let { it }
                    ?: throw error("Not found secret Key")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            } else
                if (KEY_ALGORITHM == KeyProperties.KEY_ALGORITHM_RSA){
                if (!createKeyPair()) throw error("error create key pair")

                val unrestricted = getPublicKey()?.let {
                        KeyFactory.getInstance(it.algorithm)
                            .generatePublic(X509EncodedKeySpec(it.encoded)) }
                    ?: throw error("not found public key")
                val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)
                Log.d("Andreas", "getInitializedCipherForEncryption - spec $spec")
                cipher.init(Cipher.ENCRYPT_MODE, unrestricted, spec)
            }

            CryptoResult.Result(cipher)
        }catch (e: Exception){
            Log.d("Andreas", "getInitializedCipherForEncryption" )
            e.printStackTrace()
            CryptoResult.Error(e)
        }
    }

    override fun getInitializedCipherForDecryption(
        initializationVector: ByteArray
    ): CryptoResult {
        return try{
            val cipher = getCipher()
            if (KEY_ALGORITHM == KeyProperties.KEY_ALGORITHM_RSA){
                val encryptKey = getPrivateKey()?.let { it }
                        ?: throw  error("not found private key")
                cipher.init(Cipher.DECRYPT_MODE, encryptKey);
            } else if (KEY_ALGORITHM == KeyProperties.KEY_ALGORITHM_AES){
                val secretKey = getOrCreateSecretKey()
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, initializationVector))
            }

            Log.d("Andreas", "getInitializedCipherForDecryption - inside Public Key")
            CryptoResult.Result(cipher)
        }catch (e: Exception){
            Log.d("Andreas", "getInitializedCipherForDecryption" )
            e.printStackTrace()
            CryptoResult.Error(e)
        }
    }

    override fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        val iv = if (cipher.iv == null) byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  else cipher.iv
        return CiphertextWrapper(ciphertext, iv)
//        return CiphertextWrapper(ciphertext, cipher.iv)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun decryptData(ciphertext: ByteArray, cipher: Cipher): DecryptResult {
        return try{
            val plaintext = cipher.doFinal(ciphertext)
            DecryptResult.Result(String(plaintext, Charset.forName("UTF-8")))
        }catch (e: KeyPermanentlyInvalidatedException){
            Log.d("Andreas", "KeyPermanentlyInvalidatedException")
            e.printStackTrace()
            DecryptResult.BiometricKeyChanged
        } catch (e: KeyStoreException){
            Log.d("Andreas", "KeyStoreException")
            e.printStackTrace()
            DecryptResult.BiometricKeyChanged
        } catch (e: SignatureException){
            Log.d("Andreas", "SignatureException")
            e.printStackTrace()
            DecryptResult.BiometricKeyChanged
        } catch (e : IllegalBlockSizeException){
            Log.d("Andreas", "IllegalBlockSizeException")
            e.printStackTrace()
            DecryptResult.BiometricKeyChanged
        }
    }


    private fun getCipher(): Cipher {

        val transformation = if (KEY_ALGORITHM == KeyProperties.KEY_ALGORITHM_AES) "$KEY_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
                    else "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
//        val transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
//        val cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC")
        return Cipher.getInstance(transformation)
    }

    override fun removeBiometric(keyName: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let {
            keyStore.deleteEntry(keyName)
        }
    }

    override fun persistCiphertextWrapperToSharedPrefs(
        ciphertextWrapper: CiphertextWrapper,
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ) {
        val json = Gson().toJson(ciphertextWrapper)
        context.getSharedPreferences(filename, mode).edit().putString(prefKey, json).apply()
    }

    override fun clearCiphertextWrapperToSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ) {
        context.getSharedPreferences(filename, mode).edit().remove(prefKey).apply()
//        val json = Gson().toJson(ciphertextWrapper)
//        context.getSharedPreferences(filename, mode).edit().putString(prefKey, json).apply()
    }

    override fun getCiphertextWrapperFromSharedPrefs(
        context: Context,
        filename: String,
        mode: Int,
        prefKey: String
    ): CiphertextWrapper? {
        val json = context.getSharedPreferences(filename, mode).getString(prefKey, null)
        return Gson().fromJson(json, CiphertextWrapper::class.java)
    }


//        private val ANDROID_KEYSTORE = "AndroidKeyStore"
        //    private val keyGenerator by lazy { KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")}

    @SuppressLint("NewApi")
    @TargetApi(Build.VERSION_CODES.M)
    private fun createKeyPair(): Boolean {
        var keyGenerator : KeyPairGenerator? = null
        try {
            keyGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            keyStore.load(null)

            keyGenerator.initialize(
                KeyGenParameterSpec.Builder(
                    keyName,
                    KeyProperties.PURPOSE_DECRYPT
                )
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    // Require the user to authenticate with a fingerprint to authorize
                    // every use of the private key
                    .setUserAuthenticationRequired(true)
                    .setIsStrongBoxBacked(Build.VERSION.SDK_INT > Build.VERSION_CODES.P)
                    .build()
            )
            keyGenerator.generateKeyPair()
            return true
        } catch (e: StrongBoxUnavailableException){
            try {
//                val
                if (keyGenerator==null) KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
                keyStore.load(null)

                keyGenerator?.initialize(
                    KeyGenParameterSpec.Builder(
                        keyName,
                        KeyProperties.PURPOSE_DECRYPT
                    )
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        // Require the user to authenticate with a fingerprint to authorize
                        // every use of the private key
                        .setUserAuthenticationRequired(true)
                        .build()
                )
                keyGenerator?.generateKeyPair()
                return true
            } catch (e: InvalidAlgorithmParameterException) {
                return false
            }
        } catch (e: InvalidAlgorithmParameterException) {
            return false
        }
    }

    private fun getPrivateKey(): PrivateKey? {
        var privateKey: PrivateKey? = null
//        return
        try {
            keyStore.load(null)
            privateKey = keyStore.getKey(keyName, null) as PrivateKey

//            PrivateKeyResult.Result(privateKey)
        } catch (e: Exception) {
//            PrivateKeyResult.Error(e)
            Log.d("Andreas", "Error ${e.toString()}")
            throw e
        }
        return privateKey
    }

    private fun getPublicKey(): PublicKey? {
        var publicKey: PublicKey? = null
//        return
        try {
            keyStore.load(null)
            publicKey = keyStore.getCertificate(keyName).publicKey
//            PublicKeyResult.Result(publicKey)
        } catch (e: Exception) {
            Log.d("Andreas", "Error ${e.toString()}")
            throw e
            //PublicKeyResult.Error(e)
        }

        return publicKey
    }

    fun removeBiometric() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null) // Keystore must be loaded before it can be accessed
        keyStore.getKey(keyName, null)?.let {
            keyStore.deleteEntry(keyName)
        }
    }

    private fun getOrCreateSecretKey(): SecretKey? {

        keyStore.load(null) // Initialize
        // Return SecretKey when exists
        keyStore.getKey(keyName, null)?.let { return it as SecretKey }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // if you reach here, then a new SecretKey must be generated for that keyName
            val paramsBuilder =
                KeyGenParameterSpec.Builder(
                    keyName,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
            paramsBuilder.apply {
                ENCRYPTION_BLOCK_MODE?.let{setBlockModes(ENCRYPTION_BLOCK_MODE)}
                setEncryptionPaddings(ENCRYPTION_PADDING)
                KEY_SIZE?.let{ setKeySize(it) }
                setUserAuthenticationRequired(true)
//                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
//                    setInvalidatedByBiometricEnrollment(true)
            }

            val keyGenParams = paramsBuilder.build()
            val keyGenerator = KeyGenerator.getInstance(
                KEY_ALGORITHM,
                ANDROID_KEYSTORE
            )

            keyGenerator.init(keyGenParams)
            return keyGenerator.generateKey()
        }
        return null;
    }

}


data class CiphertextWrapper(val ciphertext: ByteArray, val initializationVector: ByteArray)