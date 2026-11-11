package com.darkvault.backup

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private data class VaultDeviceCredentials(val deviceId: String, val secret: String)

private object VaultDeviceSecretStore {
    private const val alias = "ArabicVaultSupabaseDeviceKey"
    private const val prefs = "vault_supabase_secure"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    fun save(context: Context, credentials: VaultDeviceCredentials) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val plain = JSONObject()
            .put("device_id", credentials.deviceId)
            .put("device_secret", credentials.secret)
            .toString().toByteArray(StandardCharsets.UTF_8)
        val encrypted = cipher.doFinal(plain)
        val value = Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
            Base64.encodeToString(encrypted, Base64.NO_WRAP)
        context.getSharedPreferences(prefs, Context.MODE_PRIVATE).edit().putString("device", value).apply()
    }

    fun load(context: Context): VaultDeviceCredentials? = runCatching {
        val value = context.getSharedPreferences(prefs, Context.MODE_PRIVATE).getString("device", null) ?: return null
        val parts = value.split(":", limit = 2)
        require(parts.size == 2)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)))
        val json = JSONObject(String(cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), StandardCharsets.UTF_8))
        VaultDeviceCredentials(json.getString("device_id"), json.getString("device_secret"))
    }.getOrNull()

    fun clear(context: Context) {
        context.getSharedPreferences(prefs, Context.MODE_PRIVATE).edit().remove("device").apply()
    }
}

private object VaultSupabaseApi {
    const val defaultUrl = "https://vkykokoaidykjmmytqxg.supabase.co"

    private fun request(
        projectUrl: String,
        anonKey: String,
        body: JSONObject,
        deviceSecret: String? = null
    ): JSONObject {
        val base = projectUrl.trim().trimEnd('/')
        require(base.startsWith("https://")) { "يجب أن يبدأ رابط Supabase بـ https://" }
        require(anonKey.isNotBlank()) { "أدخل مفتاح Supabase العام (anon/publishable)" }
        val connection = (URL("$base/functions/v1/vault-device").openConnection() as HttpURLConnection)
        connection.requestMethod = "POST"
        connection.connectTimeout = 20000
        connection.readTimeout = 30000
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        connection.setRequestProperty("Accept", "application/json")
        connection.setRequestProperty("apikey", anonKey.trim())
        if (!deviceSecret.isNullOrBlank()) connection.setRequestProperty("x-device-key", deviceSecret)
        try {
            connection.outputStream.use { it.write(body.toString().toByteArray(StandardCharsets.UTF_8)) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val raw = stream?.use { it.readBytes() } ?: ByteArray(0)
            val response = runCatching { JSONObject(String(raw, StandardCharsets.UTF_8)) }
                .getOrElse { JSONObject().put("error", "invalid_server_response") }
            if (status !in 200..299) {
                val error = response.optString("error", "http_$status")
                throw IllegalStateException("Supabase ($status): $error")
            }
            return response
        } finally {
            connection.disconnect()
        }
    }

    fun enroll(projectUrl: String, anonKey: String, pairingCode: String, label: String): VaultDeviceCredentials {
        require(pairingCode.trim().length >= 24) { "رمز الاقتران غير مكتمل" }
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val secret = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        val response = request(
            projectUrl, anonKey,
            JSONObject()
                .put("action", "enroll")
                .put("pairing_code", pairingCode.trim())
                .put("device_secret", secret)
                .put("device_label", label.trim().ifBlank { "Android vault" }.take(80))
        )
        return VaultDeviceCredentials(response.getString("device_id"), secret)
    }

    fun poll(projectUrl: String, anonKey: String, secret: String): List<String> {
        val response = request(projectUrl, anonKey, JSONObject().put("action", "poll"), secret)
        val commands = response.optJSONArray("commands") ?: return emptyList()
        return (0 until commands.length()).map { index ->
            val item = commands.getJSONObject(index)
            val action = item.optString("action", "أمر")
            val path = item.optString("path").takeIf { it.isNotBlank() } ?: "بدون مسار"
            val status = item.optString("status", "غير معروف")
            "$action — $path — $status"
        }
    }
}

@Composable
internal fun SupabaseDevicePanel(onMessage: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var projectUrl by remember { mutableStateOf(VaultSupabaseApi.defaultUrl) }
    var anonKey by remember { mutableStateOf("") }
    var pairingCode by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("Android vault") }
    var connected by remember { mutableStateOf(VaultDeviceSecretStore.load(context) != null) }
    var deviceId by remember { mutableStateOf(VaultDeviceSecretStore.load(context)?.deviceId.orEmpty()) }
    var commands by remember { mutableStateOf<List<String>>(emptyList()) }
    var busy by remember { mutableStateOf(false) }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("ربط Supabase")
            Text("أدخل المفتاح العام فقط. لا تضع service_role key هنا أبداً.")
            OutlinedTextField(
                value = projectUrl, onValueChange = { projectUrl = it },
                modifier = Modifier.fillMaxWidth(), label = { Text("رابط مشروع Supabase") }, singleLine = true
            )
            OutlinedTextField(
                value = anonKey, onValueChange = { anonKey = it },
                modifier = Modifier.fillMaxWidth(), label = { Text("المفتاح العام anon / publishable") },
                visualTransformation = PasswordVisualTransformation(), singleLine = true
            )
            OutlinedTextField(
                value = label, onValueChange = { label = it },
                modifier = Modifier.fillMaxWidth(), label = { Text("اسم هذا الجهاز") }, singleLine = true
            )
            if (!connected) {
                OutlinedTextField(
                    value = pairingCode, onValueChange = { pairingCode = it },
                    modifier = Modifier.fillMaxWidth(), label = { Text("رمز الاقتران (صالح 15 دقيقة)") }, singleLine = true
                )
                Button(
                    onClick = {
                        scope.launch {
                            busy = true
                            runCatching {
                                withContext(Dispatchers.IO) {
                                    VaultSupabaseApi.enroll(projectUrl, anonKey, pairingCode, label)
                                }
                            }.onSuccess {
                                VaultDeviceSecretStore.save(context, it)
                                connected = true
                                deviceId = it.deviceId
                                pairingCode = ""
                                onMessage("تم ربط الجهاز وحفظ مفتاحه مشفراً على الهاتف")
                            }.onFailure { onMessage("فشل الاقتران: " + it.localizedMessage) }
                            busy = false
                        }
                    },
                    enabled = !busy && pairingCode.length >= 24 && anonKey.isNotBlank()
                ) { Text(if (busy) "جارٍ الربط..." else "اقتران هذا الجهاز") }
            } else {
                Text("الجهاز مرتبط: $deviceId")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                busy = true
                                runCatching {
                                    withContext(Dispatchers.IO) {
                                        val credentials = VaultDeviceSecretStore.load(context)
                                            ?: error("بيانات الجهاز غير موجودة")
                                        VaultSupabaseApi.poll(projectUrl, anonKey, credentials.secret)
                                    }
                                }.onSuccess {
                                    commands = it
                                    onMessage("تم الاتصال؛ عدد الأوامر الواردة: ${it.size}")
                                }.onFailure { onMessage("فشل الاتصال: " + it.localizedMessage) }
                                busy = false
                            }
                        },
                        enabled = !busy && anonKey.isNotBlank()
                    ) { Text(if (busy) "جارٍ الفحص..." else "فحص الأوامر") }
                    OutlinedButton(
                        onClick = {
                            VaultDeviceSecretStore.clear(context)
                            connected = false
                            deviceId = ""
                            commands = emptyList()
                            onMessage("فُصل الجهاز وحُذفت بيانات مفتاحه من الهاتف")
                        },
                        enabled = !busy
                    ) { Text("فصل الجهاز") }
                }
                if (commands.isNotEmpty()) {
                    Text("الأوامر الواردة (عرض فقط — لا يتم تنفيذها)")
                    commands.forEach { Text("• $it") }
                } else {
                    Text("لا توجد أوامر معروضة. اضغط فحص الأوامر للتحديث.")
                }
            }
            if (busy) Text("جارٍ تنفيذ العملية...")
        }
    }
}
