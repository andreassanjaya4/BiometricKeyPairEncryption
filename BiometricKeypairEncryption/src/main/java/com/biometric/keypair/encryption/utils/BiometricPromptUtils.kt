package com.biometric.keypair.encryption.utils

import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
//import com.biometric.keypair.encryption.DecryptCallBack
import com.biometric.keypair.encryption.response.DecryptCallBack

interface BiometricPromptUtils{
    fun createBiometricPrompt(activity: AppCompatActivity,
                              processResult: (BiometricPrompt.AuthenticationResult) -> DecryptCallBack
    ) : BiometricPrompt
    fun createPromptInfo() : BiometricPrompt.PromptInfo
}