// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.kotlin.android) apply false
    // 移除 kotlin-compose 插件引用，以避免与 AGP/KGP 1.9.x 版本的冲突
}
