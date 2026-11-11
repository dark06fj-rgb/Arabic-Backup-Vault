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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private data class RemoteFile(val path: String, val sha: String, val size: Long)

private object GitHubTokenStore {
    private const val alias = "ArabicBackupVaultGitHubToken"
    private const val prefs = "vault_github_secure"

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

    fun save(context: Context, token: String) {
        require(token.isNotBlank()) { "أدخل رمز GitHub أولاً" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val encrypted = cipher.doFinal(token.toByteArray(StandardCharsets.UTF_8))
        val value = Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
            Base64.encodeToString(encrypted, Base64.NO_WRAP)
        context.getSharedPreferences(prefs, Context.MODE_PRIVATE).edit().putString("token", value).apply()
    }

    fun load(context: Context): String? = runCatching {
        val value = context.getSharedPreferences(prefs, Context.MODE_PRIVATE).getString("token", null) ?: return null
        val parts = value.split(":", limit = 2)
        require(parts.size == 2)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)))
        String(cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), StandardCharsets.UTF_8)
    }.getOrNull()

    fun clear(context: Context) {
        context.getSharedPreferences(prefs, Context.MODE_PRIVATE).edit().remove("token").apply()
    }
}

private object GitHubApi {
    private fun enc(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun request(url: String, method: String = "GET", token: String? = null, body: ByteArray? = null): ByteArray {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.connectTimeout = 15000
        connection.readTimeout = 45000
        connection.setRequestProperty("Accept", "application/vnd.github+json")
        connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
        connection.setRequestProperty("User-Agent", "Arabic-Backup-Vault-Android")
        if (!token.isNullOrBlank()) connection.setRequestProperty("Authorization", "Bearer " + token)
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            if (code !in 200..299) {
                val detail = runCatching { JSONObject(String(bytes, StandardCharsets.UTF_8)).optString("message") }.getOrNull()
                throw IllegalStateException("GitHub رفض الطلب (" + code + ")" +
                    if (detail.isNullOrBlank()) "" else ": " + detail)
            }
            return bytes
        } finally {
            connection.disconnect()
        }
    }

    fun listFiles(repo: String, branch: String, token: String?): List<RemoteFile> {
        val url = "https://api.github.com/repos/" + repo + "/git/trees/" + enc(branch) + "?recursive=1"
        val json = JSONObject(String(request(url, token = token), StandardCharsets.UTF_8))
        check(!json.optBoolean("truncated")) { "قائمة المستودع أكبر من حد GitHub؛ لم نعرض قائمة ناقصة" }
        val tree = json.getJSONArray("tree")
        return (0 until tree.length()).mapNotNull { index ->
            val item = tree.getJSONObject(index)
            if (item.optString("type") != "blob") null
            else RemoteFile(item.getString("path"), item.optString("sha"), item.optLong("size"))
        }.sortedBy { it.path.lowercase() }
    }

    fun download(repo: String, branch: String, path: String, token: String?): ByteArray {
        val encodedPath = path.split("/").joinToString("/") { enc(it) }
        val encodedBranch = branch.split("/").joinToString("/") { enc(it) }
        return request("https://raw.githubusercontent.com/" + repo + "/" + encodedBranch + "/" + encodedPath, token = token)
    }

    fun upload(repo: String, branch: String, path: String, file: File, token: String, oldSha: String?) {
        require(file.length() <= 100L * 1024L * 1024L) { "حجم الملف يتجاوز حد الرفع المدعوم (100 ميجابايت)" }
        val payload = JSONObject()
            .put("message", "Sync from Arabic Backup Vault: " + path)
            .put("content", Base64.encodeToString(file.readBytes(), Base64.NO_WRAP))
            .put("branch", branch)
        if (!oldSha.isNullOrBlank()) payload.put("sha", oldSha)
        val encodedPath = path.split("/").joinToString("/") { enc(it) }
        request(
            "https://api.github.com/repos/" + repo + "/contents/" + encodedPath,
            method = "PUT",
            token = token,
            body = payload.toString().toByteArray(StandardCharsets.UTF_8)
        )
    }
}

@Composable
internal fun GitHubSyncPanel(
    workspace: File,
    onMessage: (String) -> Unit,
    onWorkspaceChanged: () -> Unit,
    beforeOverwrite: (String) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var repo by remember { mutableStateOf("dark06fj-rgb/GenshinAutoAssistant") }
    var branch by remember { mutableStateOf("arabic-localization-catalog") }
    var token by remember { mutableStateOf("") }
    var tokenSaved by remember { mutableStateOf(GitHubTokenStore.load(context) != null) }
    var remoteFiles by remember { mutableStateOf<List<RemoteFile>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var busyPath by remember { mutableStateOf<String?>(null) }

    fun checkedRepo(): String {
        val value = repo.trim()
        require(Regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$").matches(value)) {
            "صيغة المستودع يجب أن تكون owner/repository"
        }
        require(branch.isNotBlank() && !branch.contains("..") && !branch.startsWith("/") && !branch.endsWith("/")) {
            "اسم الفرع غير صالح"
        }
        return value
    }

    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("اتصال GitHub")
            Text("التنزيل من المستودعات العامة لا يحتاج رمزاً. الرفع يتطلب رمزاً بصلاحية Contents: Read and write لهذا المستودع فقط.")
            OutlinedTextField(
                value = repo, onValueChange = { repo = it }, modifier = Modifier.fillMaxWidth(),
                label = { Text("المستودع (owner/repository)") }, singleLine = true
            )
            OutlinedTextField(
                value = branch, onValueChange = { branch = it }, modifier = Modifier.fillMaxWidth(),
                label = { Text("الفرع") }, singleLine = true
            )
            OutlinedTextField(
                value = token, onValueChange = { token = it; tokenSaved = false },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(if (tokenSaved) "رمز GitHub محفوظ ومشفّر على الهاتف" else "رمز GitHub (للرفع فقط)") },
                visualTransformation = PasswordVisualTransformation(), singleLine = true
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        runCatching { GitHubTokenStore.save(context, token.trim()) }
                            .onSuccess { token = ""; tokenSaved = true; onMessage("حُفظ رمز GitHub مشفّراً داخل الهاتف") }
                            .onFailure { onMessage("تعذر حفظ الرمز: " + it.localizedMessage) }
                    },
                    enabled = token.isNotBlank() && !loading
                ) { Text("حفظ الرمز بأمان") }
                TextButton(
                    onClick = {
                        GitHubTokenStore.clear(context)
                        token = ""; tokenSaved = false
                        onMessage("حُذف رمز GitHub المحفوظ من الهاتف")
                    },
                    enabled = tokenSaved && !loading
                ) { Text("حذف الرمز") }
            }
            OutlinedButton(
                onClick = {
                    scope.launch {
                        loading = true
                        runCatching {
                            withContext(Dispatchers.IO) {
                                GitHubApi.listFiles(checkedRepo(), branch.trim(), GitHubTokenStore.load(context))
                            }
                        }.onSuccess {
                            remoteFiles = it
                            onMessage("تم جلب " + it.size + " ملفاً من GitHub")
                        }.onFailure { onMessage("تعذر الاتصال: " + it.localizedMessage) }
                        loading = false
                    }
                },
                enabled = !loading && busyPath == null
            ) { Text(if (loading) "جارٍ الاتصال..." else "جلب قائمة ملفات GitHub") }

            if (remoteFiles.isNotEmpty()) {
                Text("ملفات GitHub (" + remoteFiles.size + ")")
                remoteFiles.forEach { remote ->
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column(Modifier.weight(1f)) {
                            Text(remote.path)
                            Text(remote.size.toString() + " بايت")
                        }
                        TextButton(
                            onClick = {
                                scope.launch {
                                    busyPath = remote.path
                                    runCatching {
                                        withContext(Dispatchers.IO) {
                                            val destination = File(workspace, remote.path)
                                            check(destination.canonicalPath.startsWith(workspace.canonicalPath + File.separator)) {
                                                "مسار الملف خارج مساحة العمل"
                                            }
                                            val bytes = GitHubApi.download(
                                                checkedRepo(), branch.trim(), remote.path, GitHubTokenStore.load(context)
                                            )
                                            if (destination.exists()) beforeOverwrite("قبل تنزيل " + remote.path)
                                            destination.parentFile?.mkdirs()
                                            val temp = File(destination.parentFile, "." + destination.name + ".download.tmp")
                                            temp.writeBytes(bytes)
                                            if (destination.exists()) check(destination.delete()) { "تعذر استبدال الملف القديم" }
                                            check(temp.renameTo(destination)) { "تعذر تثبيت الملف المنزّل" }
                                        }
                                    }.onSuccess {
                                        onMessage("تم تنزيل " + remote.path + " إلى مساحة العمل")
                                        onWorkspaceChanged()
                                    }.onFailure { onMessage("فشل التنزيل: " + it.localizedMessage) }
                                    busyPath = null
                                }
                            },
                            enabled = busyPath == null && !loading
                        ) { Text(if (busyPath == remote.path) "..." else "تنزيل") }
                    }
                }
            }

            val localFiles = workspace.walkTopDown().filter { it.isFile }
                .sortedBy { it.relativeTo(workspace).invariantSeparatorsPath.lowercase() }.toList()
            Text("ملفات مساحة العمل (" + localFiles.size + ")")
            localFiles.forEach { file ->
                val path = file.relativeTo(workspace).invariantSeparatorsPath
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(Modifier.weight(1f)) {
                        Text(path)
                        Text(file.length().toString() + " بايت")
                    }
                    TextButton(
                        onClick = {
                            val savedToken = GitHubTokenStore.load(context)
                            if (savedToken.isNullOrBlank()) {
                                onMessage("احفظ رمز GitHub بصلاحية Contents: Read and write قبل الرفع")
                            } else {
                                scope.launch {
                                    busyPath = path
                                    runCatching {
                                        withContext(Dispatchers.IO) {
                                            val remote = GitHubApi.listFiles(checkedRepo(), branch.trim(), savedToken)
                                                .firstOrNull { it.path == path }
                                            GitHubApi.upload(checkedRepo(), branch.trim(), path, file, savedToken, remote?.sha)
                                        }
                                    }.onSuccess { onMessage("تم رفع " + path + " إلى GitHub") }
                                        .onFailure { onMessage("فشل الرفع: " + it.localizedMessage) }
                                    busyPath = null
                                }
                            }
                        },
                        enabled = busyPath == null && !loading
                    ) { Text(if (busyPath == path) "..." else "رفع") }
                }
            }
            if (loading || busyPath != null) Text("جارٍ تنفيذ العملية...")
            Text("كل ملف يُرفع بعملية commit مستقلة. لا توجد مزامنة تلقائية أو حذف للملفات البعيدة.")
        }
    }
}
