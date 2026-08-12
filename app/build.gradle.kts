plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.xiaotong6666.zygotenextprobe"
    defaultConfig {
        applicationId = "io.github.xiaotong6666.zygotenextprobe"
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            vcsInfo.include = false
            signingConfig = signingConfigs["debug"]
            optimization {
                enable = true
                keepRules {
                    includeDefault = false
                }
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        aidl = true
        buildConfig = true
    }
    defaultConfig {
        ndk {
            abiFilters += listOf("x86_64", "arm64-v8a")
        }
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
                cppFlags += "-O2"
            }
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
    packaging {
        resources {
            excludes += "**"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
    lint {
        checkReleaseBuilds = false
    }
    dependenciesInfo {
        includeInApk = false
    }
}
