package com.biometric.sample

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import com.biometric.keypair.encryption.BioKeyPairEncryption
import com.biometric.keypair.encryption.response.AuthResult
import com.biometric.keypair.encryption.response.BiometricStatus
import com.biometric.keypair.encryption.response.EnrollResult
import com.biometric.keypair.encryption.utils.BiometricSettings
import com.biometric.sample.databinding.ActivityMainBinding
import com.biometric.sample.utils.BiometricPromptUtilsUI
import com.biometric.sample.utils.MyBiometricSettings

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.decryptBtn.isEnabled = false
        binding.encryptBtn.isEnabled = false
//        setContentView(R.layout.activity_main)

        val settings = MyBiometricSettings(this)
        val encryption = BioKeyPairEncryption.Builder(this, settings).build()

        Log.d("Andreas", "here")
        when (encryption.checkBiometric()){
            BiometricStatus.SUCCESS -> {
                Log.d("Andreas", "Success")
                Toast.makeText(this, "Biometric Ready!", Toast.LENGTH_LONG).show()
                binding.encryptBtn.isEnabled = true
                when (encryption.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        binding.decryptBtn.isEnabled = true
                    }
                }
            }
            is BiometricStatus.ERROR_NONE_ENROLLED -> {
                Toast.makeText(this, "Please enabled Biometric to use this features!", Toast.LENGTH_LONG).show()
                binding.encryptBtn.isEnabled = false
            }
            is BiometricStatus.ERROR_KEY_CHANGED -> {
                Toast.makeText(this, "Please re-encrypt, changed on Biometric!", Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(this, "Device not support biometric, try on another device!", Toast.LENGTH_LONG).show()
            }
        }
        Log.d("Andreas", "here2")
        binding.encryptBtn.setOnClickListener{
            Log.d("Andreas", "here clicked")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!binding.inputWord.text.isEmpty())
                    when (val enrollRslt = encryption.enrollAndEncrypt(this, binding.inputWord.text.toString())){
                        is EnrollResult.Error -> {
                            Toast.makeText(this, "Error encrypt ${enrollRslt.errorString}", Toast.LENGTH_LONG).show()
                            enrollRslt.exception?.printStackTrace()
                        }
                        EnrollResult.Result ->{
                            Toast.makeText(this, "Success Encrypt!", Toast.LENGTH_LONG).show()
                            binding.decryptBtn.isEnabled = true
                        }

                    }
                else{
                    Toast.makeText(this, "Please input word!", Toast.LENGTH_LONG).show()
                }
            }
            else{
                Toast.makeText(this, "Device Not Supported!", Toast.LENGTH_LONG).show()
            }
        }

        binding.decryptBtn.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                when (encryption.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        when (val authResult = encryption.authAndDecrypt(this, BiometricPromptUtilsUI)){
                            is AuthResult.Error -> {
                                Toast.makeText(this, "Error Auth ${authResult.errorString}!", Toast.LENGTH_LONG).show()
                                authResult.exception?.printStackTrace()
                            }
                        }
                    }
                    else -> {
                        Toast.makeText(this, "Please do encrypt first!", Toast.LENGTH_LONG).show()
                    }
                }
            }
            else{
                Toast.makeText(this, "Device Not Supported!", Toast.LENGTH_LONG).show()
            }
        }
    }
}