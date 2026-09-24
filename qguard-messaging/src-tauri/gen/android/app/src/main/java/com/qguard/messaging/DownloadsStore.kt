package com.qguard.messaging

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import org.json.JSONObject

/**
 * Writes user-requested files into the PUBLIC Downloads collection
 * (`Download/QGuard/`), where the Files app shows them.
 *
 * Why this exists: every "download" in the app used to be a web-style
 * `<a download>` click on a blob URL. Android's WebView has no download manager
 * for that — without a DownloadListener it drops the click silently, and a
 * blob: URL could not be handed to one anyway. So a decrypted chat attachment,
 * the MFA recovery codes, the vault recovery key and the audit export all
 * reported success while no file was ever written.
 *
 * MediaStore (API 29+, this app's minSdk) needs no storage permission for files
 * the app creates itself. Protocol, driven from Rust over JNI
 * (src-tauri/src/security/public_downloads.rs):
 *
 *  1. `begin()` inserts a PENDING row and returns its `content://` URI. Pending
 *     rows are invisible to other apps, so a half-written file is never exposed.
 *  2. Rust opens that URI through the content-resolver fd bridge
 *     (security/content_uri.rs) and streams the bytes in.
 *  3. `finish()` clears the pending flag and reports the name MediaStore settled
 *     on (it de-duplicates: `report.pdf` -> `report (1).pdf`), so the UI can say
 *     exactly where the file went.
 *  4. `abort()` deletes the row if anything failed.
 *
 * Every method returns a String — never Unit — because Rust looks each one up
 * with a String-returning JNI descriptor; a void method has a different
 * descriptor and fails with NoSuchMethodError (see VaultFolderPicker.reset).
 * Failures are returned in-band as "error:<reason>".
 */
object DownloadsStore {
    private val RELATIVE_DIR = Environment.DIRECTORY_DOWNLOADS + "/QGuard"

    /** Insert a pending Downloads row. Returns its content URI or "error:<reason>". */
    @JvmStatic
    fun begin(context: Context, displayName: String, declaredMimeType: String): String {
        return try {
            val name = withExtension(displayName, declaredMimeType)
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, name)
                put(MediaStore.MediaColumns.MIME_TYPE, mimeTypeFor(name))
                put(MediaStore.MediaColumns.RELATIVE_PATH, RELATIVE_DIR)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val uri = context.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return "error:the Downloads folder refused the new file"
            uri.toString()
        } catch (error: Exception) {
            "error:${error.message ?: "could not create the file in Downloads"}"
        }
    }

    /**
     * Publish a fully written row. Returns {"name":..,"relativePath":..} or
     * "error:<reason>".
     */
    @JvmStatic
    fun finish(context: Context, uri: String): String {
        return try {
            val target = Uri.parse(uri)
            val published = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            if (context.contentResolver.update(target, published, null, null) < 1) {
                return "error:the saved file could not be published to Downloads"
            }
            var name = ""
            var relativePath = RELATIVE_DIR
            context.contentResolver.query(
                target,
                arrayOf(MediaStore.MediaColumns.DISPLAY_NAME, MediaStore.MediaColumns.RELATIVE_PATH),
                null,
                null,
                null,
            )?.use { cursor ->
                if (cursor.moveToFirst()) {
                    name = cursor.getString(0) ?: ""
                    relativePath = cursor.getString(1) ?: relativePath
                }
            }
            JSONObject()
                .put("name", name)
                .put("relativePath", relativePath.trimEnd('/'))
                .toString()
        } catch (error: Exception) {
            "error:${error.message ?: "could not publish the file"}"
        }
    }

    /** Delete a row that was never completed. Returns "ok" or "error:<reason>". */
    @JvmStatic
    fun abort(context: Context, uri: String): String {
        return try {
            context.contentResolver.delete(Uri.parse(uri), null, null)
            "ok"
        } catch (error: Exception) {
            "error:${error.message ?: "could not remove the incomplete file"}"
        }
    }

    /**
     * The MIME type is derived from the extension, as VaultFolderPicker does:
     * MediaStore appends the MIME type's own extension when the two disagree, so
     * a declared type that does not match the name (`invoice.jpg` sent as
     * `application/pdf`) would silently rename the file. Unknown extensions stay
     * `application/octet-stream`, which never triggers a rename.
     */
    private fun mimeTypeFor(displayName: String): String {
        val extension = displayName.substringAfterLast('.', "")
        if (extension.isEmpty()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension.lowercase())
            ?: "application/octet-stream"
    }

    /**
     * A name with no extension (a voice note, a pasted image) would be saved as a
     * file nothing can open. Only then is the declared type consulted, to give it
     * the extension that type normally carries.
     */
    private fun withExtension(displayName: String, declaredMimeType: String): String {
        if (displayName.substringAfterLast('.', "").isNotEmpty()) return displayName
        val base = declaredMimeType.substringBefore(';').trim().lowercase()
        val extension = MimeTypeMap.getSingleton().getExtensionFromMimeType(base)
        return if (extension.isNullOrEmpty()) displayName else "$displayName.$extension"
    }
}
