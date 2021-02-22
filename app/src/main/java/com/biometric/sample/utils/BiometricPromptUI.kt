package com.biometric.sample.utils

import androidx.biometric.BiometricPrompt
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.biometric.keypair.encryption.response.DecryptCallBack
import com.biometric.keypair.encryption.utils.BiometricPromptUtils

object BiometricPromptUtilsUI : BiometricPromptUtils {
    private const val TAG = "BiometricPromptUtils"

    override fun createBiometricPrompt(
        activity: AppCompatActivity,
        processResult: (BiometricPrompt.AuthenticationResult) -> DecryptCallBack
    ) : BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(activity)
        val callBack = object : BiometricPrompt.AuthenticationCallback(){
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.d(TAG, "errCode is $errorCode and errString is: $errString")

            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "Authentication was successful")
                when (val resultEncryption = processResult(result)){
                    is DecryptCallBack.Result -> { Log.d("Andreas", "Result " + resultEncryption.data) }
                    is DecryptCallBack.Error -> { Log.d("Andreas", "Error " + resultEncryption.error)  }
                }
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
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