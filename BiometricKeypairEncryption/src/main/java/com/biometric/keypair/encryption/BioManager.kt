package com.biometric.keypair.encryption

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.hardware.fingerprint.FingerprintManagerCompat
import com.biometric.keypair.encryption.response.AuthResult
import com.biometric.keypair.encryption.response.BiometricStatus
import com.biometric.keypair.encryption.response.EnrollResult
import com.biometric.keypair.encryption.utils.BiometricPromptUtils
import com.biometric.keypair.encryption.utils.BiometricSettings

interface BioManager {

    fun checkBiometric() : BiometricStatus
    fun isFingerEnabled(): BiometricSettings.BiometricFuncStatus
    fun enableFingerPrint(status: BiometricSettings.BiometricFuncStatus)

    fun isSupportedSDK(): Boolean
//    fun checkSelfPermission(): Boolean
//    fun resetAll()

    @RequiresApi(Build.VERSION_CODES.M)
    fun enrollAndEncrypt(activity: AppCompatActivity, plainText: String, biometricUtils: BiometricPromptUtils? = null): EnrollResult
    @RequiresApi(Build.VERSION_CODES.M)
    fun authAndDecrypt(activity: AppCompatActivity, biometricUtils: BiometricPromptUtils): AuthResult
}