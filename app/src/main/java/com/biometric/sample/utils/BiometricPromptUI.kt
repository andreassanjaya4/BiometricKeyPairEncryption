package com.biometric.sample.utils

import androidx.biometric.BiometricPrompt
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
//import com.biometric.keypair.encryption.response.DecryptCallBack
import com.biometric.keypair.encryption.response.EncryptionCallBack
import com.biometric.keypair.encryption.utils.BiometricPromptUtils

interface BioUpdateUI{
    fun success(data: String)
    fun error(err : String)
}

class BiometricPromptUtilsUI(private val callback: BioUpdateUI): BiometricPromptUtils {
    private val TAG = "BiometricPromptUtils"

    
    override fun createBiometricPrompt(
        activity: AppCompatActivity,
        processResult: (BiometricPrompt.AuthenticationResult) -> EncryptionCallBack
    ) : BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(activity)
        val callBack = object : BiometricPrompt.AuthenticationCallback(){
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
//                super.onAuthenticationError(errorCode, errString)
                callback.error("$errorCode-$errString")
                Log.d(TAG, "errCode is $errorCode and errString is: $errString")
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Authentication was successful")
                when (val resultEncryption = processResult(result)){
                    is EncryptionCallBack.Result -> { Log.d("Andreas", "Result " + resultEncryption.data)
                        callback.success(resultEncryption.data)
                    }
                    is EncryptionCallBack.Error -> { Log.d("Andreas", "Error " + resultEncryption.error) 
                        callback.error(resultEncryption.error)
                    }
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                callback.error("Authentication Failed")
                Log.d(TAG, "User biometric rejected.")
            }

        }

        return BiometricPrompt(activity, executor, callBack)
    }

    override fun createPromptInfo() : BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder().apply {
            setTitle("Biometric Keypair Encryption")
            setSubtitle("Please login")
//            setDescription("This is description")
            setConfirmationRequired(false)
            setNegativeButtonText("Cancel")

        }.build()
}