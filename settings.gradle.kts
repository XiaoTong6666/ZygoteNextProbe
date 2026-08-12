@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories {
        google {
            content {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        val agp = "9.3.0"
        id("com.android.application") version agp
        id("com.android.library") version agp
        id("com.android.settings") version agp
        id("org.jetbrains.kotlin.android") version "2.3.0"
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
    }
}

plugins {
    id("com.android.settings")
}

android {
    compileSdk {
        version = release(37) {
            minorApiLevel = 0
        }
    }
    minSdk {
        version = release(37)
    }
    targetSdk {
        version = release(37)
    }
    buildToolsVersion = "37.0.0"
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
enableFeaturePreview("STABLE_CONFIGURATION_CACHE")

rootProject.name = "ZygoteNextProbe"
include(":app")
