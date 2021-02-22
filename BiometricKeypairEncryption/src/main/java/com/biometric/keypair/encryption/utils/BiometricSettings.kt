package com.biometric.keypair.encryption.utils

interface BiometricSettings {
    sealed class BiometricFuncStatus{
        object Enabled: BiometricFuncStatus()
        object Disabled: BiometricFuncStatus()
        object Unknown: BiometricFuncStatus()
    }
    fun isEnabled(): BiometricFuncStatus
    fun setBiometricStatus(status: BiometricFuncStatus)
}