package com.biometric.keypair.encryption.manager

import android.content.Context
import android.os.Build
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import com.google.gson.Gson
import java.nio.charset.Charset
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource


/**
 * Handles encryption and decryption
 */
interface CryptographyManager {

    fun getInitializedCipherForEncryption(pKey: Key): CryptoResult

    fun getInitializedCipherForDecryption(initializationVector: ByteArray, pKey: Key): CryptoResult

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

fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()

/**
 * To get an instance of this private CryptographyManagerImpl class, use the top-level function
 * fun CryptographyManager(): CryptographyManager = CryptographyManagerImpl()
 */

private class CryptographyManagerImpl : CryptographyManager {

    private val KEY_SIZE = 256
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
    private val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
    private val ENCRYPTION_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES

//    private var byte[] the_iv =

    override fun getInitializedCipherForEncryption(pKey : Key): CryptoResult {
        return try{
            val cipher = getCipher()
            Log.d("Andreas", "getInitializedCipherForEncryption ${cipher}")
            Log.d("Andreas", "getInitializedCipherForEncryption - Result")
//                BioAuthManager.PublicKeyPemResult.Result(publicKey.publicKey.toPEM())
            Log.d("Andreas", "getInitializedCipherForEncryption - Key $pKey")
            val unrestricted: PublicKey = KeyFactory.getInstance(pKey.algorithm)
                .generatePublic(X509EncodedKeySpec(pKey.encoded))
            Log.d("Andreas", "getInitializedCipherForEncryption - unrestricted $unrestricted")
            val spec = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)
//                    val spec = OAEPParameterSpec(
//                            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
            Log.d("Andreas", "getInitializedCipherForEncryption - spec $spec")
            cipher.init(Cipher.ENCRYPT_MODE, unrestricted, spec)
            Log.d("Andreas", "getInitializedCipherForEncryption - inside Public Key")
            CryptoResult.Result(cipher)
        }catch (e: Exception){
            Log.d("Andreas", "getInitializedCipherForEncryption" )
            e.printStackTrace()
            CryptoResult.Error(e)
        }
    }

    override fun getInitializedCipherForDecryption(
        initializationVector: ByteArray,
        pKey : Key
    ): CryptoResult {
        return try{
            val cipher = getCipher()
            cipher.init(Cipher.DECRYPT_MODE, pKey);
            Log.d("Andreas", "getInitializedCipherForDecryption - inside Public Key")
            CryptoResult.Result(cipher)
        }catch (e: Exception){
            Log.d("Andreas", "getInitializedCipherForDecryption" )
            e.printStackTrace()
            CryptoResult.Error(e)
        }

//        Log.d("Andreas", "getInitializedCipherForDecryption - return value")
//        return cipher
    }

    override fun encryptData(plaintext: String, cipher: Cipher): CiphertextWrapper {
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charset.forName("UTF-8")))
        val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
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
//        val transformation = "$ENCRYPTION_ALGORITHM/$ENCRYPTION_BLOCK_MODE/$ENCRYPTION_PADDING"
        val transformation = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

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
}


data class CiphertextWrapper(val ciphertext: ByteArray, val initializationVector: ByteArray)