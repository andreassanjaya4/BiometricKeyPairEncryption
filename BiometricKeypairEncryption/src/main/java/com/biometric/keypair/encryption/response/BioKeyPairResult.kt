package com.biometric.keypair.encryption.response

import java.lang.Exception
import java.security.PrivateKey
import java.security.PublicKey

sealed class DecryptCallBack {
    class Result(val data: String) : DecryptCallBack()
    class Error(val error: String) : DecryptCallBack()
}

sealed class EnrollResult {
    class Error(val errorString: String, val exception: Exception?) : EnrollResult()
    object Result: EnrollResult()
}

sealed class AuthResult {
    class Error(val errorString: String, val exception: Exception?) : AuthResult()
    object Result: AuthResult()
}

//sealed class PublicKeyResult{
//    class Error(val error: Exception?): PublicKeyResult()
//    class Result(val publicKey: PublicKey): PublicKeyResult()
//}
//sealed class PrivateKeyResult{
//    class Error(val error: Exception?): PrivateKeyResult()
//    class Result(val key: PrivateKey): PrivateKeyResult()
//}