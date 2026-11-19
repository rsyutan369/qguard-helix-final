package com.qguard.messaging

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import android.webkit.MimeTypeMap
import org.json.JSONArray
import org.json.JSONObject

/**
 * Storage Access Framework destination-folder bridge for the Quantum Vault.
 *
 * The Tauri dialog plugin has no mobile folder picker, so "choose where to save
 * the encrypted/decrypted file" was impossible on Android — encrypted containers
 * were forced into the app-private vault directory and decrypted output went
 * through a one-shot save dialog. This object adds the missing piece:
 *
 *  1. `launch()` opens `ACTION_OPEN_DOCUMENT_TREE` (the system folder picker).
 *  2. `onActivityResult()` takes a PERSISTABLE read/write grant on the chosen
 *     tree, so the folder — and every document the vault creates inside it —
 *     stays readable and writable across app restarts. That durability is what
 *     lets a user-chosen location hold registry-tracked `.qvault` containers
 *     (decrypt / verify / delete keep working later).
 *  3. `createDocument()` creates a named file inside a granted tree and returns
 *     its `content://` document URI, which the existing content-resolver fd
 *     bridge (security/content_uri.rs) streams into.
 *
 * Called from Rust over JNI (src-tauri/src/security/saf_folder.rs). The picker
 * is asynchronous by nature (an Activity result), so the outcome is published
 * into a small JSON state blob that the Rust side polls — the same pattern as
 * PlayBilling.kt.
 */
object VaultFolderPicker {
    const val REQUEST_CODE = 0x5641
    private const val XFER_REQUEST_CODE = 0x5846

    private val lock = Any()
    private var state: String = "idle"
    private var treeUri: String = ""
    private var detail: String = ""
    private var pendingRequest = 0

    private fun publish(next: String, uri: String = "", message: String = "") {
        synchronized(lock) {
            state = next
            treeUri = uri
            detail = message
            if (next != "pending") pendingRequest = 0
        }
    }

    /** Open the system folder picker. Returns "ok" or "error:<reason>". */
    @JvmStatic
    fun launch(context: Context): String = launchPicker(context, REQUEST_CODE)

    @JvmStatic
    fun launchSource(context: Context): String = launchPicker(context, XFER_REQUEST_CODE)

    private fun launchPicker(context: Context, request: Int): String {
        // Rust passes the Application context (tao >= 0.37), never the Activity.
        val activity = CurrentActivity.resolve(context)
            ?: return "error:the app is not in the foreground — reopen QGuard and try again"
        synchronized(lock) {
            publish("pending")
            pendingRequest = request
        }
        return try {
            activity.runOnUiThread {
                try {
                    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        if (request == REQUEST_CODE) addFlags(
                                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
                        )
                    }
                    activity.startActivityForResult(intent, request)
                } catch (error: Exception) {
                    publish("error", "", error.message ?: "folder picker unavailable")
                }
            }
            "ok"
        } catch (error: Exception) {
            publish("error", "", error.message ?: "folder picker unavailable")
            "error:${error.message}"
        }
    }

    /** Current picker outcome: {"state":..,"uri":..,"label":..,"detail":..}. */
    @JvmStatic
    fun getStateJson(context: Context): String {
        val json = JSONObject()
        synchronized(lock) {
            json.put("state", state)
            json.put("uri", treeUri)
            json.put("detail", detail)
        }
        val uri = json.optString("uri")
        json.put("label", if (uri.isEmpty()) "" else describeTree(context, uri))
        return json.toString()
    }

    // Returns "ok" (not Unit) because Rust invokes this through the same
    // String-returning JNI signature as launch/getStateJson (see
    // call_context_string in saf_folder.rs). A void-returning `reset` compiles
    // fine but has a DIFFERENT JNI descriptor ((Context)V vs (Context)Ljava/lang/String;),
    // so the lookup fails with NoSuchMethodError on every call — which is what
    // made every encrypt/decrypt on Android fail before the folder picker ever
    // opened, reported to the user as a false "cancelled".
    @JvmStatic
    fun reset(context: Context): String {
        publish("idle")
        return "ok"
    }

    /**
     * MainActivity forwards the Activity result here. A cancelled picker is a
     * normal outcome, not an error.
     */
    fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?) {
        if (synchronized(lock) { state != "pending" || pendingRequest != requestCode }) return
        val uri = if (resultCode == Activity.RESULT_OK) data?.data else null
        if (uri == null) {
            publish("cancelled")
            return
        }
        // Persist the grant so the destination survives an app restart. Without
        // this the URI would be revoked when the task ends and every registry
        // entry saved there would become unreadable.
        if (requestCode == REQUEST_CODE) runCatching {
            val flags = (data?.flags ?: 0) and
                (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            val takeFlags = if (flags == 0) {
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            } else {
                flags
            }
            activity.contentResolver.takePersistableUriPermission(uri, takeFlags)
        }
        publish("selected", uri.toString())
    }

    /** Return only bounded files inside the read-only tree chosen for XFER. */
    @JvmStatic
    fun enumerateSource(context: Context, tree: String): String {
        return try {
            val uri = Uri.parse(tree)
            require(uri.scheme == "content" && DocumentsContract.isTreeUri(uri)) { "invalid source folder" }
            val root = DocumentsContract.getTreeDocumentId(uri)
            val resolver = context.contentResolver
            val name = resolver.query(
                DocumentsContract.buildDocumentUriUsingTree(uri, root),
                arrayOf(Document.COLUMN_DISPLAY_NAME), null, null, null,
            )?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
                ?: error("the provider did not report a folder name")
            require(validSourceName(name)) { "invalid source folder name" }
            val pending = ArrayDeque<Triple<String, String, Int>>()
            pending.addLast(Triple(root, name, 1))
            val seen = hashSetOf(root)
            val files = JSONArray()
            val columns = arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE, Document.COLUMN_SIZE, Document.COLUMN_FLAGS)
            while (pending.isNotEmpty()) {
                val (parent, prefix, depth) = pending.removeFirst()
                val children = DocumentsContract.buildChildDocumentsUriUsingTree(uri, parent)
                resolver.query(children, columns, null, null, null)?.use { cursor ->
                    while (cursor.moveToNext()) {
                        val id = cursor.getString(0) ?: error("missing document identity")
                        val leaf = cursor.getString(1) ?: error("missing document name")
                        val mime = cursor.getString(2) ?: error("missing document type")
                        val path = "$prefix/$leaf"
                        require(validSourceName(leaf) && path.toByteArray(Charsets.UTF_8).size <= 512 && depth < 16) { "a file path is invalid or too deeply nested" }
                        require(seen.size < 512 && seen.add(id)) { "the source tree is too large or contains a repeated document" }
                        if (mime == Document.MIME_TYPE_DIR) {
                            pending.addLast(Triple(id, path, depth + 1))
                        } else {
                            require(cursor.getInt(4) and Document.FLAG_VIRTUAL_DOCUMENT == 0) { "virtual files must be downloaded before sharing" }
                            require(files.length() < 128) { "choose a folder with at most 128 files" }
                            files.put(JSONObject().apply {
                                put("path", path)
                                put("uri", DocumentsContract.buildDocumentUriUsingTree(uri, id).toString())
                                if (!cursor.isNull(3) && cursor.getLong(3) >= 0L) put("size", cursor.getLong(3))
                            })
                        }
                    }
                } ?: error("could not read the selected folder")
            }
            require(files.length() > 0) { "the selected folder contains no files" }
            JSONObject().put("name", name).put("files", files).toString()
        } catch (error: Exception) {
            "error:${error.message ?: "could not read the selected folder"}"
        }
    }

    private fun validSourceName(name: String): Boolean = name.isNotBlank() && name != "." && name != ".." &&
        name.none { it == '/' || it == '\\' || it.isISOControl() }

    /**
     * Create `displayName` inside the granted tree and return its document URI.
     * Returns "error:<reason>" on failure.
     *
     * The MIME type is derived from the requested extension: the platform
     * appends the MIME type's own extension when the two disagree, so passing a
     * blanket `application/octet-stream` would turn `report.pdf` into
     * `report.pdf.bin`.
     */
    @JvmStatic
    fun createDocument(context: Context, tree: String, displayName: String): String {
        return try {
            val treeUriValue = Uri.parse(tree)
            val parent = DocumentsContract.buildDocumentUriUsingTree(
                treeUriValue,
                DocumentsContract.getTreeDocumentId(treeUriValue),
            )
            val created = DocumentsContract.createDocument(
                context.contentResolver,
                parent,
                mimeTypeFor(displayName),
                displayName,
            ) ?: return "error:the selected folder rejected a new file"
            created.toString()
        } catch (error: SecurityException) {
            "error:access to the selected folder was revoked — choose it again"
        } catch (error: Exception) {
            "error:${error.message ?: "could not create the file"}"
        }
    }

    /** Permanently delete a document created in a granted tree. */
    @JvmStatic
    fun deleteDocument(context: Context, documentUri: String): String {
        return try {
            val deleted = DocumentsContract.deleteDocument(context.contentResolver, Uri.parse(documentUri))
            if (deleted) "ok" else "error:the file could not be deleted"
        } catch (error: Exception) {
            "error:${error.message ?: "could not delete the file"}"
        }
    }

    /** Human-readable folder label, e.g. `Internal storage / Download/Vault`. */
    @JvmStatic
    fun describeTree(context: Context, tree: String): String {
        return try {
            val docId = DocumentsContract.getTreeDocumentId(Uri.parse(tree))
            val parts = docId.split(":", limit = 2)
            val volume = when {
                parts.size < 2 -> ""
                parts[0].equals("primary", ignoreCase = true) -> "Internal storage"
                else -> parts[0]
            }
            val path = if (parts.size == 2) parts[1] else docId
            listOf(volume, path).filter { it.isNotBlank() }.joinToString(" / ")
        } catch (error: Exception) {
            tree
        }
    }

    private fun mimeTypeFor(displayName: String): String {
        val extension = displayName.substringAfterLast('.', "")
        if (extension.isEmpty()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension.lowercase())
            ?: "application/octet-stream"
    }
}
