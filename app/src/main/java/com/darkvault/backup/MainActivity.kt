package com.darkvault.backup

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class MainActivity : ComponentActivity() {
    private val workspace by lazy { File(filesDir, "workspace").apply { mkdirs() } }
    private val backups by lazy { File(filesDir, "backups").apply { mkdirs() } }
    private val stagingRoot by lazy { File(cacheDir, "restore-staging").apply { mkdirs() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { VaultScreen() }
    }

    private fun stamp(): String =
        SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date()) + "_" + UUID.randomUUID().toString().take(8)

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun listFiles(root: File): List<File> =
        root.walkTopDown().filter { it.isFile }.sortedBy { it.relativeTo(root).invariantSeparatorsPath }.toList()

    private fun writeManifest(root: File) {
        val entries = listFiles(root).filter { it.name != "manifest.sha256" }
        File(root, "manifest.sha256").bufferedWriter(Charsets.UTF_8).use { writer ->
            entries.forEach { file ->
                writer.append(sha256(file)).append("  ")
                    .append(file.relativeTo(root).invariantSeparatorsPath).append('\n')
            }
        }
    }

    private fun verifyManifest(root: File): String {
        val manifest = File(root, "manifest.sha256")
        if (!manifest.isFile) return "ملف التحقق مفقود"
        val expected = linkedMapOf<String, String>()
        manifest.readLines(Charsets.UTF_8).forEach { line ->
            if (line.length < 67 || line.substring(0, 64).any { it !in "0123456789abcdefABCDEF" } || line.substring(64, 66) != "  ")
                return "صيغة سجل التحقق غير صالحة"
            val hash = line.substring(0, 64).lowercase()
            val path = line.substring(66)
            if (path.isBlank() || path.startsWith("/") || path.split('/').any { it == ".." } || expected.put(path, hash) != null)
                return "مسار مكرر أو غير آمن في سجل التحقق"
        }
        val actualFiles = listFiles(root).filter { it.name != "manifest.sha256" }
        val actualPaths = actualFiles.map { it.relativeTo(root).invariantSeparatorsPath }.toSet()
        if (actualPaths != expected.keys) return "قائمة الملفات لا تطابق سجل التحقق"
        for (file in actualFiles) {
            val path = file.relativeTo(root).invariantSeparatorsPath
            if (sha256(file) != expected[path]) return "فشل فحص سلامة الملف: $path"
        }
        return "سليمة (${actualFiles.size} ملف)"
    }

    private fun createSnapshot(label: String = "نسخة تلقائية"): File {
        val temporary = File(backups, ".tmp_${stamp()}")
        check(temporary.mkdirs()) { "تعذر إنشاء مجلد النسخة المؤقت" }
        try {
            val data = File(temporary, "files")
            runCatching { workspace.copyRecursively(data, overwrite = true) }.getOrElse { throw IllegalStateException("تعذر نسخ مساحة العمل", it) }
            writeManifest(data)
            File(temporary, "INFO.txt").writeText("$label\n${Date()}\n", Charsets.UTF_8)
            val final = File(backups, stamp())
            check(temporary.renameTo(final)) { "تعذر تثبيت النسخة الاحتياطية" }
            return final
        } catch (error: Throwable) {
            temporary.deleteRecursively()
            throw error
        }
    }

    private fun safeName(name: String): String =
        name.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[^\\p{L}\\p{N}._ -]"), "_")
            .take(120).ifBlank { "imported_file" }

    private fun queryName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor -> if (cursor.moveToFirst()) return cursor.getString(0) }
        return null
    }

    private fun importUri(uri: Uri) {
        val name = safeName(queryName(uri) ?: "ملف")
        val destination = File(workspace, name)
        val temporary = File(workspace, ".incoming_${UUID.randomUUID()}")
        try {
            contentResolver.openInputStream(uri)?.use { input ->
                temporary.outputStream().buffered().use { output -> input.copyTo(output) }
            } ?: error("تعذر قراءة الملف")
            if (destination.exists()) {
                createSnapshot("قبل استبدال $name")
                val previous = File(stagingRoot, "previous_${UUID.randomUUID()}")
                check(destination.renameTo(previous)) { "تعذر حفظ الملف القديم مؤقتاً" }
                try {
                    check(temporary.renameTo(destination)) { "تعذر تثبيت الملف الجديد" }
                    previous.delete()
                } catch (error: Throwable) {
                    if (destination.exists()) destination.delete()
                    check(previous.renameTo(destination)) { "تعذر استرجاع الملف القديم؛ احتفظنا بنسخته المؤقتة: ${previous.name}" }
                    throw error
                }
            } else {
                check(temporary.renameTo(destination)) { "تعذر حفظ الملف المستورد" }
            }
        } finally {
            temporary.delete()
        }
    }

    private fun replaceWorkspaceFrom(source: File) {
        val stage = File(stagingRoot, UUID.randomUUID().toString())
        val rollback = File(stagingRoot, "rollback_${UUID.randomUUID()}")
        try {
            runCatching { source.copyRecursively(stage, overwrite = true) }.getOrElse { throw IllegalStateException("تعذر تجهيز الملفات للاستعادة", it) }
            if (workspace.exists()) check(workspace.renameTo(rollback)) { "تعذر حفظ مساحة العمل الحالية" }
            if (!stage.renameTo(workspace)) {
                if (rollback.exists()) rollback.renameTo(workspace)
                error("تعذر تثبيت الملفات المستعادة؛ تمت محاولة إعادة الحالة السابقة")
            }
            rollback.deleteRecursively()
        } finally {
            stage.deleteRecursively()
            if (rollback.exists() && !workspace.exists()) rollback.renameTo(workspace)
        }
    }

    private fun restore(snapshot: File) {
        val saved = File(snapshot, "files")
        val result = verifyManifest(saved)
        check(result.startsWith("سليمة")) { "النسخة غير سليمة: $result" }
        createSnapshot("قبل الاستعادة")
        replaceWorkspaceFrom(saved)
    }

    private fun exportSnapshot(snapshot: File, output: Uri) {
        val data = File(snapshot, "files")
        check(verifyManifest(data).startsWith("سليمة")) { "لا يمكن تصدير نسخة تالفة" }
        contentResolver.openOutputStream(output)?.use { stream ->
            ZipOutputStream(stream).use { zip ->
                snapshot.walkTopDown().filter { it.isFile }.forEach { file ->
                    val relative = file.relativeTo(snapshot).invariantSeparatorsPath
                    zip.putNextEntry(ZipEntry(relative))
                    file.inputStream().buffered().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
            }
        } ?: error("تعذر إنشاء ملف التصدير")
    }

    private fun importBackupZip(uri: Uri) {
        val temp = File(stagingRoot, "import_${UUID.randomUUID()}")
        check(temp.mkdirs()) { "تعذر إنشاء مساحة الاستيراد" }
        try {
            var totalBytes = 0L
            var entries = 0
            val seenPaths = mutableSetOf<String>()
            contentResolver.openInputStream(uri)?.use { raw ->
                ZipInputStream(raw.buffered()).use { zip ->
                    while (true) {
                        val entry = zip.nextEntry ?: break
                        entries++
                        check(entries <= 5000) { "عدد ملفات ZIP أكبر من الحد المسموح" }
                        val path = entry.name.replace('\\', '/').trimEnd('/')
                        check(path.isNotBlank() && !path.startsWith("/") && path.split('/').none { it == ".." || it == "." || it.isBlank() }) {
                            "ملف ZIP يحتوي مساراً غير آمن"
                        }
                        check(path == "INFO.txt" || path.startsWith("files/")) {
                            "ملف ZIP ليس نسخة صادرة من خزنة النسخ الاحتياطية"
                        }
                        check(seenPaths.add(path)) { "ملف ZIP يحتوي مساراً مكرراً" }
                        if (!entry.isDirectory) {
                            val out = File(temp, path)
                            check(out.canonicalPath.startsWith(temp.canonicalPath + File.separator)) { "مسار ZIP خارج مجلد الاستيراد" }
                            out.parentFile?.mkdirs()
                            out.outputStream().buffered().use { output ->
                                val buffer = ByteArray(64 * 1024)
                                while (true) {
                                    val count = zip.read(buffer)
                                    if (count < 0) break
                                    totalBytes += count
                                    check(totalBytes <= 1024L * 1024L * 1024L) { "حجم ZIP يتجاوز 1 جيجابايت" }
                                    output.write(buffer, 0, count)
                                }
                            }
                        }
                        zip.closeEntry()
                    }
                }
            } ?: error("تعذر قراءة ملف ZIP")
            val data = File(temp, "files")
            val verification = verifyManifest(data)
            check(verification.startsWith("سليمة")) { "فشل التحقق من النسخة: $verification" }
            createSnapshot("قبل استيراد نسخة خارجية")
            replaceWorkspaceFrom(data)
        } finally {
            temp.deleteRecursively()
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun VaultScreen() {
        var refresh by remember { mutableIntStateOf(0) }
        var message by remember { mutableStateOf("الحفظ محلي ويعمل دون إنترنت") }
        var busy by remember { mutableStateOf(false) }
        var selected by remember { mutableStateOf<File?>(null) }
        var restoreTarget by remember { mutableStateOf<File?>(null) }

        val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) lifecycleScope.launch {
                busy = true
                runCatching { withContext(Dispatchers.IO) { importUri(uri) } }
                    .onSuccess { message = "تم استيراد الملف بأمان" }
                    .onFailure { message = "فشل الاستيراد: ${it.localizedMessage}" }
                refresh++; busy = false
            }
        }
        val zipImporter = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) lifecycleScope.launch {
                busy = true
                runCatching { withContext(Dispatchers.IO) { importBackupZip(uri) } }
                    .onSuccess { message = "تم التحقق من النسخة واستيرادها" }
                    .onFailure { message = "رُفض ملف النسخة: ${it.localizedMessage}" }
                refresh++; busy = false
            }
        }
        val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
            val item = selected
            if (uri != null && item != null) lifecycleScope.launch {
                busy = true
                runCatching { withContext(Dispatchers.IO) { exportSnapshot(item, uri) } }
                    .onSuccess { message = "تم تصدير النسخة بعد التحقق من سلامتها" }
                    .onFailure { message = "فشل التصدير: ${it.localizedMessage}" }
                busy = false
            }
        }

        val files = remember(refresh) {
            listFiles(workspace).sortedBy { it.relativeTo(workspace).invariantSeparatorsPath.lowercase() }
        }
        val snapshots = remember(refresh) { backups.listFiles()?.filter { it.isDirectory && !it.name.startsWith(".tmp_") }?.sortedByDescending { it.name } ?: emptyList() }

        MaterialTheme {
            Scaffold(topBar = { TopAppBar(title = { Text("خزنة النسخ الاحتياطية") }) }) { padding ->
                LazyColumn(Modifier.fillMaxSize().padding(padding).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    item { Text("حماية ملفاتك دون إنترنت", style = MaterialTheme.typography.titleMedium) }
                    item { Text(message, style = MaterialTheme.typography.bodyMedium) }
                    item {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { importer.launch(arrayOf("*/*")) }, enabled = !busy) {
                                Icon(Icons.Default.Add, null); Spacer(Modifier.width(6.dp)); Text("استيراد ملف")
                            }
                            OutlinedButton(onClick = {
                                lifecycleScope.launch {
                                    busy = true
                                    runCatching { withContext(Dispatchers.IO) { createSnapshot("نسخة يدوية") } }
                                        .onSuccess { message = "تم إنشاء نسخة احتياطية مع بصمات SHA-256" }
                                        .onFailure { message = "تعذر إنشاء النسخة: ${it.localizedMessage}" }
                                    refresh++; busy = false
                                }
                            }, enabled = !busy) { Text("نسخ الآن") }
                        }
                    }
                    item {
                        OutlinedButton(onClick = { zipImporter.launch(arrayOf("application/zip", "application/octet-stream")) }, enabled = !busy) {
                            Text("استيراد نسخة ZIP والتحقق منها")
                        }
                    }
                    item {
                        GitHubSyncPanel(
                            workspace = workspace,
                            onMessage = { message = it },
                            onWorkspaceChanged = { refresh++ },
                            beforeOverwrite = { label -> createSnapshot(label) }
                        )
                    }
                    if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                    item { Text("ملفات مساحة العمل (${files.size})", style = MaterialTheme.typography.titleMedium) }
                    if (files.isEmpty()) item { Text("لا توجد ملفات بعد. استورد ملفاتك للبدء.") }
                    items(files, key = { it.relativeTo(workspace).invariantSeparatorsPath }) { file ->
                        ListItem(
                            headlineContent = { Text(file.relativeTo(workspace).invariantSeparatorsPath) },
                            supportingContent = { Text("${file.length()} بايت") },
                            leadingContent = { Icon(Icons.Default.InsertDriveFile, null) }
                        )
                        HorizontalDivider()
                    }
                    item { Text("النسخ الاحتياطية (${snapshots.size})", style = MaterialTheme.typography.titleMedium) }
                    if (snapshots.isEmpty()) item { Text("ستظهر النسخ التي تنشئها هنا.") }
                    items(snapshots, key = { it.name }) { snapshot ->
                        var checkResult by remember(snapshot.name) { mutableStateOf<String?>(null) }
                        Card {
                            Column(Modifier.fillMaxWidth().padding(12.dp)) {
                                Text(snapshot.name, style = MaterialTheme.typography.titleSmall)
                                if (checkResult != null) Text(checkResult!!, style = MaterialTheme.typography.bodySmall)
                                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                    TextButton(onClick = {
                                        lifecycleScope.launch {
                                            val result = withContext(Dispatchers.IO) { verifyManifest(File(snapshot, "files")) }
                                            checkResult = result
                                        }
                                    }, enabled = !busy) { Text("فحص السلامة") }
                                    TextButton(onClick = { restoreTarget = snapshot }, enabled = !busy) { Text("استعادة") }
                                    TextButton(onClick = {
                                        selected = snapshot
                                        exporter.launch("ArabicVault-${snapshot.name}.zip")
                                    }, enabled = !busy) { Text("تصدير ZIP") }
                                }
                            }
                        }
                    }
                    item {
                        Text(
                            "تنبيه: النسخ داخل التطبيق تُحذف إذا أزلت التطبيق أو مسحت بياناته. صدّر ZIP إلى مكان آمن بشكل دوري.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }
        if (restoreTarget != null) {
            AlertDialog(
                onDismissRequest = { restoreTarget = null },
                title = { Text("تأكيد الاستعادة") },
                text = { Text("سيتم فحص بصمات الملفات أولاً وحفظ الوضع الحالي قبل الاستعادة. هل تريد المتابعة؟") },
                confirmButton = {
                    TextButton(onClick = {
                        val target = restoreTarget!!
                        restoreTarget = null
                        lifecycleScope.launch {
                            busy = true
                            runCatching { withContext(Dispatchers.IO) { restore(target) } }
                                .onSuccess { message = "تمت الاستعادة بعد التحقق وحفظ الحالة السابقة" }
                                .onFailure { message = "فشلت الاستعادة: ${it.localizedMessage}" }
                            refresh++; busy = false
                        }
                    }) { Text("استعادة آمنة") }
                },
                dismissButton = { TextButton(onClick = { restoreTarget = null }) { Text("إلغاء") } }
            )
        }
    }
}
