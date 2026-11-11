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
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class MainActivity : ComponentActivity() {
    private val workspace by lazy { File(filesDir, "workspace").apply { mkdirs() } }
    private val backups by lazy { File(filesDir, "backups").apply { mkdirs() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { VaultScreen() }
    }

    private fun stamp(): String = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())

    private fun createSnapshot(label: String = "نسخة تلقائية"): File {
        val target = File(backups, "${stamp()}_${label.hashCode().toUInt().toString(16)}")
        target.mkdirs()
        val data = File(target, "files")
        if (workspace.exists()) workspace.copyRecursively(data, overwrite = true)
        File(target, "INFO.txt").writeText("$label\nWed Nov 11 2026 14:23:16 GMT+0000 (Coordinated Universal Time)\n")
        return target
    }

    private fun safeName(name: String): String =
        name.substringAfterLast('/').substringAfterLast('\\')
            .replace(Regex("[^\\p{L}\\p{N}._ -]"), "_")
            .take(120).ifBlank { "imported_file" }

    private fun importUri(uri: Uri) {
        val name = safeName(queryName(uri) ?: "ملف")
        val destination = File(workspace, name)
        if (destination.exists()) createSnapshot("قبل استبدال $name")
        contentResolver.openInputStream(uri)?.use { input ->
            destination.outputStream().use { output -> input.copyTo(output) }
        } ?: error("تعذر قراءة الملف")
    }

    private fun queryName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { c -> if (c.moveToFirst()) return c.getString(0) }
        return null
    }

    private fun restore(snapshot: File) {
        createSnapshot("قبل الاستعادة")
        val saved = File(snapshot, "files")
        if (!saved.exists()) error("النسخة لا تحتوي مجلد الملفات")
        workspace.deleteRecursively()
        workspace.mkdirs()
        saved.copyRecursively(workspace, overwrite = true)
    }

    private fun exportSnapshot(snapshot: File, output: Uri) {
        contentResolver.openOutputStream(output)?.use { stream ->
            ZipOutputStream(stream).use { zip ->
                snapshot.walkTopDown().filter { it.isFile }.forEach { file ->
                    val relative = file.relativeTo(snapshot).invariantSeparatorsPath
                    zip.putNextEntry(ZipEntry(relative))
                    file.inputStream().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
            }
        } ?: error("تعذر إنشاء ملف التصدير")
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun VaultScreen() {
        var refresh by remember { mutableIntStateOf(0) }
        var message by remember { mutableStateOf("ملفاتك محفوظة محلياً على هذا الهاتف") }
        var busy by remember { mutableStateOf(false) }
        var selected by remember { mutableStateOf<File?>(null) }
        val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) lifecycleScope.launch {
                busy = true
                runCatching { withContext(Dispatchers.IO) { importUri(uri) } }
                    .onSuccess { message = "تم استيراد الملف وحفظ نسخة احتياطية عند الاستبدال" }
                    .onFailure { message = "فشل الاستيراد: ${it.localizedMessage}" }
                refresh++; busy = false
            }
        }
        val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
            val item = selected
            if (uri != null && item != null) lifecycleScope.launch {
                busy = true
                runCatching { withContext(Dispatchers.IO) { exportSnapshot(item, uri) } }
                    .onSuccess { message = "تم تصدير النسخة الاحتياطية" }
                    .onFailure { message = "فشل التصدير: ${it.localizedMessage}" }
                busy = false
            }
        }

        val files = remember(refresh) { workspace.listFiles()?.sortedBy { it.name.lowercase() } ?: emptyList() }
        val snapshots = remember(refresh) { backups.listFiles()?.filter { it.isDirectory }?.sortedByDescending { it.name } ?: emptyList() }

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
                                    runCatching { withContext(Dispatchers.IO) { createSnapshot() } }
                                        .onSuccess { message = "تم إنشاء نسخة احتياطية جديدة" }
                                        .onFailure { message = "تعذر إنشاء النسخة: ${it.localizedMessage}" }
                                    refresh++; busy = false
                                }
                            }, enabled = !busy) { Text("نسخ الآن") }
                        }
                    }
                    if (busy) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
                    item { Text("ملفات مساحة العمل (${files.size})", style = MaterialTheme.typography.titleMedium) }
                    if (files.isEmpty()) item { Text("لا توجد ملفات بعد. استورد ملفاتك للبدء.") }
                    items(files, key = { it.name }) { file ->
                        ListItem(headlineContent = { Text(file.name) }, supportingContent = { Text("${file.length()} بايت") }, leadingContent = { Icon(Icons.Default.InsertDriveFile, null) })
                        HorizontalDivider()
                    }
                    item { Text("النسخ الاحتياطية (${snapshots.size})", style = MaterialTheme.typography.titleMedium) }
                    if (snapshots.isEmpty()) item { Text("ستظهر النسخ التي تنشئها هنا.") }
                    items(snapshots, key = { it.name }) { snapshot ->
                        Card {
                            Column(Modifier.fillMaxWidth().padding(12.dp)) {
                                Text(snapshot.name, style = MaterialTheme.typography.titleSmall)
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    TextButton(onClick = {
                                        lifecycleScope.launch {
                                            busy = true
                                            runCatching { withContext(Dispatchers.IO) { restore(snapshot) } }
                                                .onSuccess { message = "تمت الاستعادة، وحُفظت الحالة السابقة أولاً" }
                                                .onFailure { message = "فشلت الاستعادة: ${it.localizedMessage}" }
                                            refresh++; busy = false
                                        }
                                    }, enabled = !busy) { Text("استعادة") }
                                    TextButton(onClick = {
                                        selected = snapshot
                                        exporter.launch("ArabicVault-${snapshot.name}.zip")
                                    }, enabled = !busy) { Text("تصدير ZIP") }
                                }
                            }
                        }
                    }
                    item {
                        Text("تنبيه: النسخ داخل التطبيق تُحذف إذا أزلت التطبيق أو مسحت بياناته. صدّر نسخة ZIP إلى مكان آمن بشكل دوري.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
}
