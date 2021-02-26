package com.biometric.sample

import android.content.Intent
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import com.biometric.keypair.encryption.BiometricEncryption
import com.biometric.keypair.encryption.response.AuthResult
import com.biometric.keypair.encryption.response.BiometricStatus
import com.biometric.keypair.encryption.response.EnrollResult
import com.biometric.keypair.encryption.utils.BiometricSettings
import com.biometric.sample.databinding.ActivityMainBinding
import com.biometric.sample.utils.BioUpdateUI
import com.biometric.sample.utils.BiometricPromptUtilsUI
import com.biometric.sample.utils.MyBiometricSettings
import kotlinx.android.synthetic.main.activity_main.view.*

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    private val REQUEST_ENROLL_BIOMETRIC = 101
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.decryptBtnAes.isEnabled = false
        binding.encryptBtnAes.isEnabled = false

        binding.decryptBtnRsa.isEnabled = false
        binding.encryptBtnRsa.isEnabled = false

//        setContentView(R.layout.activity_main)

        val settingsAES = MyBiometricSettings(this, "aesEncryption")
        val encryptionAES = BiometricEncryption.Builder(this, settingsAES)
            .withAESSEttings()
            .configuration( "biometric_pref", "aesEncryption")
            .build()

        Log.d("Andreas", "here")
        when (encryptionAES.checkBiometric()){
            BiometricStatus.SUCCESS -> {
                Log.d("Andreas", "Success")
                Toast.makeText(this, "Biometric Ready!", Toast.LENGTH_LONG).show()
                binding.encryptBtnAes.isEnabled = true
                when (encryptionAES.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        binding.decryptBtnAes.isEnabled = true
                    }
                }
            }
            is BiometricStatus.ERROR_NONE_ENROLLED -> {
                Toast.makeText(this, "Please enabled Biometric to use this features!", Toast.LENGTH_LONG).show()
                binding.encryptBtnAes.isEnabled = false

                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                    putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BIOMETRIC_STRONG)
                }
                startActivityForResult(enrollIntent, REQUEST_ENROLL_BIOMETRIC)


            }
            is BiometricStatus.ERROR_KEY_CHANGED -> {
                Toast.makeText(this, "Please re-encrypt, changed on Biometric!", Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(this, "Device not support biometric, try on another device!", Toast.LENGTH_LONG).show()
            }
        }
        binding.checkBiometric.setOnClickListener{
            when (encryptionAES.checkBiometric()){
                BiometricStatus.ERROR_UNKNOWN -> Log.d("Andreas", "Check Error Unknown")
                BiometricStatus.ERROR_NO_HARDWARE -> Log.d("Andreas", "Check Error ERROR_NO_HARDWARE")
                BiometricStatus.ERROR_KEY_CHANGED -> Log.d("Andreas", "Check Error ERROR_KEY_CHANGED")
                BiometricStatus.ERROR_NONE_ENROLLED -> Log.d("Andreas", "Check Error ERROR_NONE_ENROLLED")
                BiometricStatus.SUCCESS -> Log.d("Andreas", "Check Error Success")
            }
        }

        Log.d("Andreas", "here2")
        binding.encryptBtnAes.setOnClickListener{
            Log.d("Andreas", "here clicked")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!binding.inputWord.text.isEmpty())
                    when (val enrollRslt = encryptionAES.enrollAndEncrypt(this, binding.inputWord.text.toString(),
                        BiometricPromptUtilsUI(object: BioUpdateUI{
                            override fun success(data: String) {
                                binding.aesEncrypt.text = data
                                binding.decryptBtnAes.isEnabled = true
                                Toast.makeText(applicationContext, "Success Encrypt!", Toast.LENGTH_LONG).show()
                            }

                            override fun error(err: String) {

                            }

                        })
                    )){

                        is EnrollResult.Error -> {
                            Toast.makeText(this, "Error encrypt ${enrollRslt.errorString}", Toast.LENGTH_LONG).show()
                            enrollRslt.exception?.printStackTrace()
                        }
                        is EnrollResult.Result ->{
                            Toast.makeText(this, "Success Encrypt!", Toast.LENGTH_LONG).show()
                            binding.decryptBtnAes.isEnabled = true
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

        binding.decryptBtnAes.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                when (encryptionAES.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        when (val authResult = encryptionAES.authAndDecrypt(this,
                            BiometricPromptUtilsUI(object: BioUpdateUI{
                                override fun success(data: String) {

                                }

                                override fun error(err: String) {

                                }

                            })
                        )){
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

        val settingsRSA = MyBiometricSettings(this, "rsaEncryption")
        val encryptionRSA = BiometricEncryption.Builder(this, settingsRSA)
            .withRSASettings()
            .configuration( "biometric_pref", "rsaEncryption")
            .build()
        when (encryptionRSA.checkBiometric()){
            BiometricStatus.SUCCESS -> {
                Log.d("Andreas", "Success")
                Toast.makeText(this, "Biometric Ready!", Toast.LENGTH_LONG).show()
                binding.encryptBtnRsa.isEnabled = true
                when (encryptionRSA.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        binding.decryptBtnRsa.isEnabled = true
                    }
                }
            }
            is BiometricStatus.ERROR_NONE_ENROLLED -> {
                Toast.makeText(this, "Please enabled Biometric to use this features!", Toast.LENGTH_LONG).show()
                binding.encryptBtnRsa.isEnabled = false

            }
            is BiometricStatus.ERROR_KEY_CHANGED -> {
                Toast.makeText(this, "Please re-encrypt, changed on Biometric!", Toast.LENGTH_LONG).show()
            }
            else -> {
                Toast.makeText(this, "Device not support biometric, try on another device!", Toast.LENGTH_LONG).show()
            }
        }


        binding.encryptBtnRsa.setOnClickListener{
            Log.d("Andreas", "here clicked")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!binding.inputWord.text.isEmpty())
                    when (val enrollRslt = encryptionRSA.enrollAndEncrypt(this, binding.inputWord.text.toString())){
                        is EnrollResult.Error -> {
                            Toast.makeText(this, "Error encrypt ${enrollRslt.errorString}", Toast.LENGTH_LONG).show()
                            enrollRslt.exception?.printStackTrace()
                        }
                        is EnrollResult.Result ->{
                            Toast.makeText(this, "Success Encrypt!", Toast.LENGTH_LONG).show()
                            binding.decryptBtnRsa.isEnabled = true
                            binding.rsaEncrypt.text = enrollRslt.encData
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

        binding.decryptBtnRsa.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                when (encryptionRSA.isFingerEnabled()) {
                    BiometricSettings.BiometricFuncStatus.Enabled -> {
                        when (val authResult = encryptionRSA.authAndDecrypt(this,
                            BiometricPromptUtilsUI(object: BioUpdateUI{
                                override fun success(data: String) {

                                }

                                override fun error(err: String) {

                                }

                            })

                        )){
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