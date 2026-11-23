plugins {
    alias(libs.plugins.android.application)
}

val runNumber = (System.getenv("GITHUB_RUN_NUMBER") ?: "1").toInt()

android {
    namespace = "dev.ayana.test"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.ayana.test"
        minSdk = 29
        targetSdk = 35
        versionCode = runNumber
        versionName = "0.$runNumber"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // Fixed test-only key: every build can be installed over the previous one.
    signingConfigs {
        create("test") {
            storeFile = file("test-only.keystore")
            storePassword = "ayanatest"
            keyAlias = "test"
            keyPassword = "ayanatest"
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("test")
        }
        getByName("release") {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("test")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // jniLibs holds executables (launcher, probe) built by android/native.sh.
    // Legacy packaging extracts them to nativeLibraryDir, the one place an
    // app may execute files from.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
