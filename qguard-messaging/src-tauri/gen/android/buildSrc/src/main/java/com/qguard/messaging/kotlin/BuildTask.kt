import java.io.ByteArrayOutputStream
import java.io.File
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null
    @Input
    var target: String? = null
    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        val executable = """npm""";
        try {
            runTauriCli(executable)
        } catch (e: Exception) {
            if (Os.isFamily(Os.FAMILY_WINDOWS)) {
                // Try different Windows-specific extensions
                val fallbacks = listOf(
                    "$executable.exe",
                    "$executable.cmd",
                    "$executable.bat",
                )

                var lastException: Exception = e
                for (fallback in fallbacks) {
                    try {
                        runTauriCli(fallback)
                        return
                    } catch (fallbackException: Exception) {
                        lastException = fallbackException
                    }
                }
                throw lastException
            } else {
                throw e;
            }
        }
    }

    fun runTauriCli(executable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")
        val args = listOf("run", "--", "tauri", "android", "android-studio-script");

        // Capture output so the ONLY failure we are willing to repair — the
        // Windows "symbolic link creation requires Developer Mode" error thrown
        // when tauri links the built .so into jniLibs — can be identified
        // precisely. Everything else still fails the build.
        val output = ByteArrayOutputStream()
        val result = project.exec {
            workingDir(File(project.projectDir, rootDirRel))
            executable(executable)
            args(args)
            standardOutput = output
            errorOutput = output
            isIgnoreExitValue = true
            if (project.logger.isEnabled(LogLevel.DEBUG)) {
                args("-vv")
            } else if (project.logger.isEnabled(LogLevel.INFO)) {
                args("-v")
            }
            if (release) {
                args("--release")
            }
            args(listOf("--target", target))
        }

        val text = output.toString()
        print(text)

        if (result.exitValue == 0) {
            return
        }

        val symlinkFailure = text.contains("SeCreateSymbolicLinkPrivilege") ||
            text.contains("Creation symbolic link is not allowed")
        if (symlinkFailure && placeBuiltLibrary(rootDirRel, target, release)) {
            logger.warn(
                "tauri could not symlink the built library (Windows Developer Mode is off); " +
                "copied it into jniLibs instead."
            )
            return
        }

        throw GradleException("`$executable $args` failed with exit code ${result.exitValue}")
    }

    /**
     * Copies the cargo-built .so into app/src/main/jniLibs/<abi>/ — the exact
     * destination tauri fails to symlink without Developer Mode. The .so is
     * guaranteed fresh here: cargo completes (and revalidates) the build before
     * the CLI ever attempts the symlink.
     */
    private fun placeBuiltLibrary(rootDirRel: String, target: String, release: Boolean): Boolean {
        val triple = when (target) {
            "aarch64" -> "aarch64-linux-android"
            "armv7" -> "armv7-linux-androideabi"
            "i686" -> "i686-linux-android"
            "x86_64" -> "x86_64-linux-android"
            else -> return false
        }
        val abi = when (target) {
            "aarch64" -> "arm64-v8a"
            "armv7" -> "armeabi-v7a"
            "i686" -> "x86"
            "x86_64" -> "x86_64"
            else -> return false
        }

        val rootDir = File(project.projectDir, rootDirRel).canonicalFile
        val profile = if (release) "release" else "debug"
        val soName = "libqguard_messaging_lib.so"

        val targetDirs = mutableListOf<File>()
        System.getenv("CARGO_TARGET_DIR")?.let { targetDirs.add(File(it)) }
        // Honor a `[build] target-dir` redirect in src-tauri/.cargo/config.toml.
        val cargoConfig = File(rootDir, ".cargo/config.toml")
        if (cargoConfig.exists()) {
            val match = Regex("""^\s*target-dir\s*=\s*"(.+)"\s*$""", RegexOption.MULTILINE)
                .find(cargoConfig.readText())
            match?.groupValues?.get(1)?.let { targetDirs.add(File(it)) }
        }
        targetDirs.add(File(rootDir, "target"))

        val source = targetDirs
            .map { File(it, "$triple/$profile/$soName") }
            .firstOrNull { it.isFile }
            ?: return false

        val destDir = File(project.projectDir, "src/main/jniLibs/$abi")
        destDir.mkdirs()
        val dest = File(destDir, soName)
        if (dest.exists()) {
            dest.delete()
        }
        source.copyTo(dest, overwrite = true)
        return true
    }
}
