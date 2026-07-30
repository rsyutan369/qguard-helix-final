package com.qguard.messaging

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.webkit.MimeTypeMap
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

    private val lock = Any()
    private var state: String = "idle"
    private var treeUri: String = ""
    private var detail: String = ""

    private fun publish(next: String, uri: String = "", message: String = "") {
        synchronized(lock) {
            state = next
            treeUri = uri
            detail = message
        }
    }

    /** Open the system folder picker. Returns "ok" or "error:<reason>". */
    @JvmStatic
    fun launch(context: Context): String {
        val activity = context as? Activity
            ?: return "error:vault folder picker needs the app activity"
        publish("pending")
        return try {
            activity.runOnUiThread {
                try {
                    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                        addFlags(
                            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
                        )
                    }
                    activity.startActivityForResult(intent, REQUEST_CODE)
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

    @JvmStatic
    fun reset(context: Context) {
        publish("idle")
    }

    /**
     * MainActivity forwards the Activity result here. A cancelled picker is a
     * normal outcome, not an error.
     */
    fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != REQUEST_CODE) return
        val uri = if (resultCode == Activity.RESULT_OK) data?.data else null
        if (uri == null) {
            publish("cancelled")
            return
        }
        // Persist the grant so the destination survives an app restart. Without
        // this the URI would be revoked when the task ends and every registry
        // entry saved there would become unreadable.
        runCatching {
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
