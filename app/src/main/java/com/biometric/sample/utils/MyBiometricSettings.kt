package com.biometric.sample.utils

import android.content.Context
import android.content.SharedPreferences
import com.biometric.keypair.encryption.utils.BiometricSettings


class MyBiometricSettings(context: Context, prefName: String): BiometricSettings {

    private var prefs: SharedPreferences = context.applicationContext.getSharedPreferences(
        prefName, Context.MODE_PRIVATE)

    override fun isEnabled(): BiometricSettings.BiometricFuncStatus {
        return when(prefs.getString("BiometricEnabled", null)){
            "true" -> BiometricSettings.BiometricFuncStatus.Enabled
            "false" -> BiometricSettings.BiometricFuncStatus.Disabled
            else -> BiometricSettings.BiometricFuncStatus.Unknown
        }
    }

    override fun setBiometricStatus(status: BiometricSettings.BiometricFuncStatus) {
        val enabled = when(status){
            BiometricSettings.BiometricFuncStatus.Enabled -> "true"
            BiometricSettings.BiometricFuncStatus.Disabled -> "false"
            else -> "-"
        }
        prefs.edit().putString("BiometricEnabled", enabled).apply()
    }
}