package com.biometric.keypair.encryption.response

sealed class BiometricStatus{
    object ERROR_KEY_CHANGED: BiometricStatus()
    object ERROR_NO_HARDWARE: BiometricStatus()
    object DISABLED: BiometricStatus()
    object ERROR_UNKNOWN: BiometricStatus()
    object ERROR_NONE_ENROLLED:BiometricStatus()
    object SUCCESS:BiometricStatus()
}