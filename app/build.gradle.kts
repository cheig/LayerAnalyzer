plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
}

val releaseKeystorePath = providers.environmentVariable("LAYERANALYZER_KEYSTORE_PATH")
val releaseKeystorePassword = providers.environmentVariable("LAYERANALYZER_KEYSTORE_PASSWORD")
val releaseKeyAlias = providers.environmentVariable("LAYERANALYZER_KEY_ALIAS")
val releaseKeyPassword = providers.environmentVariable("LAYERANALYZER_KEY_PASSWORD")
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseKeystorePassword,
    releaseKeyAlias,
    releaseKeyPassword
).all { it.isPresent }

// G.729 is enabled by default. LayerAnalyzer is licensed under GPL-3.0.
// Disabling the codec does not change the application license.
val enableG729 = (project.findProperty("layanalyzerEnableG729") as String?)?.toBoolean() ?: true

// RTP4-NAT-08: the iLBC decoder is WebRTC's libilbc (BSD-3), a licence that is
// GPL-compatible, so enabling it does not change the conveyed licence of the
// build the way bcg729 does. The default is nevertheless OFF, because this card
// is optional and OFF is the state that cannot affect anything else: with it
// off, third_party/libilbc is not compiled and not on any include path, so the
// canonical id "iLBC" is unknown and callers report it unsupported.
//
// Turn it on with -PlayanalyzerEnableIlbc=true.
// Declared at file scope for the same reason as enableG729 above: the debug and
// emulator variants share one `defaultConfig`, so assembleDebug (arm64-v8a) and
// assembleEmulator (x86_64) both receive the value.
val enableIlbc = (project.findProperty("layanalyzerEnableIlbc") as String?)?.toBoolean() ?: false

// P0 experiments only; production builds never compile or package the probe.
val enableTlsProbe = providers.gradleProperty("layanalyzerTlsProbe").orElse("false").get().toBooleanStrict()
val enableTls = providers.gradleProperty("layanalyzerEnableTls").get().toBooleanStrict()
// NIO is the only implementation. Reject an obsolete launch request instead of ignoring it.
require(!providers.gradleProperty("layanalyzerSocksMode").isPresent) {
    "layanalyzerSocksMode has been removed; NIO is the only implementation and BLOCKING is unsupported"
}
// Expanded default tier; device acceptance is reported separately from configuration.
val socksTcpLimit = providers.gradleProperty("layanalyzerSocksTcp").orElse("1024").get().toInt()
val socksUdpLimit = providers.gradleProperty("layanalyzerSocksUdp").orElse("256").get().toInt()
val socksAuthLimit = providers.gradleProperty("layanalyzerSocksAuth").orElse("128").get().toInt()
val socksCapacityValidation = providers.gradleProperty("layanalyzerSocksCapacityValidation").orElse("false").get().toBooleanStrict()
require(socksTcpLimit in setOf(64, 128, 256, 512, 1024) && socksUdpLimit in setOf(64, 128, 256) && socksAuthLimit in setOf(64, 128))
require((socksTcpLimit == 1024 && socksUdpLimit == 256 && socksAuthLimit == 128) ||
    (socksTcpLimit == 64 && socksUdpLimit == 64 && socksAuthLimit == 64) ||
    socksCapacityValidation) { "Non-default SOCKS tiers require layanalyzerSocksCapacityValidation=true" }
val tlsGoExecutable = providers.gradleProperty("layanalyzerTlsGo").orElse("go")
val tlsPythonExecutable = providers.gradleProperty("layanalyzerTlsPython").orElse(
    if (System.getProperty("os.name").startsWith("Windows")) "python" else "python3"
)
val tlsProbeLibDir = rootProject.file(
    providers.gradleProperty("layanalyzerTlsProbeLibDir").orElse("build/tls-003").get()
)

android {
    namespace = "com.example.layanalyzer"
    // 降级 compileSdk 到 34，与 AGP 8.4.1 保持更好的兼容性
    compileSdk = 34

    testBuildType = providers.gradleProperty("layanalyzerTestBuildType").orElse("debug").get().also {
        require(it == "debug" || it == "emulator") { "Device tests require debug or emulator" }
    }

    defaultConfig {
        // Keep the source namespace stable for the JNI ABI, but use a
        // production application id instead of Android's example placeholder.
        applicationId = "com.layeranalyzer.android"
        minSdk = 26
        multiDexEnabled = true
        targetSdk = 34
        versionCode = 5
        versionName = "1.1.0"
        ndkVersion = "27.0.12077973"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("boolean", "TLS_ENABLED", enableTls.toString())
        buildConfigField("int", "SOCKS_TCP_LIMIT", socksTcpLimit.toString())
        buildConfigField("int", "SOCKS_UDP_LIMIT", socksUdpLimit.toString())
        buildConfigField("int", "SOCKS_AUTH_LIMIT", socksAuthLimit.toString())
        vectorDrawables { useSupportLibrary = true }
        externalNativeBuild {
            cmake {
                cppFlags("")
                arguments(
                    "-DANDROID_STL=c++_shared",
                    "-DLAYANALYZER_ENABLE_TLS=${if (enableTls) "ON" else "OFF"}",
                    // Replaces, rather than appends to, the previous single
                    // "-DANDROID_STL=c++_shared" argument: a duplicated -D for
                    // the same cache variable makes CMake warn and override.
                    "-DLAYANALYZER_ENABLE_G729=${if (enableG729) "ON" else "OFF"}",
                    // Same -D carrying the same cache variable, so it replaces
                    // rather than appends for the same reason as the line above.
                    "-DLAYANALYZER_ENABLE_ILBC=${if (enableIlbc) "ON" else "OFF"}"
                )
                targets += listOf("layanalyzer", "layanalyzer_tunnel")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    if (hasReleaseSigning) {
        signingConfigs {
            create("release") {
                storeFile = file(releaseKeystorePath.get())
                storePassword = releaseKeystorePassword.get()
                keyAlias = releaseKeyAlias.get()
                keyPassword = releaseKeyPassword.get()
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        debug {
            // Distinct application id so a debug build installs alongside the
            // release app instead of colliding with it (different signing keys
            // would otherwise fail with INSTALL_FAILED_UPDATE_INCOMPATIBLE).
            applicationIdSuffix = ".debug"
            buildConfigField("boolean", "TLS_PROBE_ENABLED", enableTlsProbe.toString())
            externalNativeBuild.cmake.arguments("-DLAYANALYZER_TLS_PROBE=${if (enableTlsProbe) "ON" else "OFF"}")
            signingConfig = signingConfigs.getByName("debug")
            isMinifyEnabled = false
            isJniDebuggable = true
            ndk { abiFilters += listOf("arm64-v8a") }
        }
        create("emulator") {
            // Keep x86_64 support in an explicit Android Studio build variant
            // instead of increasing every debug APK with a second ABI.
            initWith(getByName("debug"))
            matchingFallbacks += listOf("debug")
            // initWith copies the debug suffix, so re-set it to keep the
            // emulator variant installable next to an arm64 debug build.
            applicationIdSuffix = ".emulator"
            ndk {
                abiFilters.clear()
                abiFilters += listOf("x86_64")
            }
        }
        release {
            buildConfigField("boolean", "TLS_PROBE_ENABLED", "false")
            externalNativeBuild.cmake.arguments("-DLAYANALYZER_TLS_PROBE=OFF")
            isMinifyEnabled = true
            ndk { abiFilters += listOf("arm64-v8a") }
            proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = "1.8" }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.11" }
    lint {
        // OPT-L10N-02: any string in values/ without a values-zh-rCN/
        // translation must fail lintDebug, so translation debt cannot grow.
        // (In this AGP's Kotlin DSL `error` is a MutableSet<String>, not the
        // Groovy-era error(vararg String) method.)
        error.add("MissingTranslation")
        // Pin the pre-existing unrelated failures (2 MissingPermission spots
        // in RadioSourceAdapters.kt, present before OPT-L10N-02) so lintDebug
        // can gate on translation debt.  The baseline records only those
        // existing issues; newly missing translations still fail the build.
        baseline = file("lint-baseline.xml")
    }
    packaging {
        // Full license texts and component notices are explicitly bundled in
        // assets/licenses/ and THIRD_PARTY_NOTICES.txt, and readable offline.
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
        jniLibs {
            // Android 15+ (API 35+) 要求 16 KB 页面对齐
            // 移除 useLegacyPackaging，使用现代对齐方式
            useLegacyPackaging = false
        }
    }
}

run {
    // Passive TLS tests use production JNI with probe OFF. Canonical TLS-401
    // fixtures are always test-only and never packaged in the application APK.
    val tlsFixtureAssets = layout.buildDirectory.dir("generated/tlsFixtureAssets")
    val stageTlsFixtures = tasks.register<Sync>("stageTlsFixtureAssets") {
        from(rootProject.file("native_build/verification/tls/fixtures")) {
            include("manifest.json", "*/*.pcap", "*/*.keys",
                "*/ca.pem", "*/client-result.json", "*/golden-body.bin")
            into("tls/fixtures")
        }
        into(tlsFixtureAssets)
    }
    android.sourceSets.getByName("androidTest").assets.srcDir(tlsFixtureAssets)
    tasks.configureEach {
        if ((name.startsWith("merge") && name.endsWith("AndroidTestAssets")) ||
            (name.startsWith("generate") && name.endsWith("AndroidTestLintModel")) ||
            (name.startsWith("lintAnalyze") && name.endsWith("AndroidTest"))) {
            // Lint consumes the same generated assets as the test APK. Without
            // this edge, assembling tests and linting in one invocation fails
            // Gradle's producer/consumer validation (or reads stale fixtures).
            dependsOn(stageTlsFixtures)
        }
    }
}

if (enableTls) {
    mapOf("debug" to "arm64-v8a", "emulator" to "x86_64", "release" to "arm64-v8a").forEach { (variant, abi) ->
        val suffix = variant.replaceFirstChar { it.uppercase() }
        val output = rootProject.layout.buildDirectory.dir("tls-production/$variant")
        val script = rootProject.file("native_build/scripts/build_tls_engine.py")
        val buildGo = tasks.register<Exec>("build${suffix}TlsEngine") {
            inputs.files(rootProject.fileTree("native_go/tlsbridge") { include("**/*.go", "**/*.h", "go.mod", "go.sum", "dependencies.json", "toolchain-lock.json") })
            inputs.file(script)
            inputs.file(rootProject.file("tools/check_tls_dependencies.py"))
            inputs.file(rootProject.file("docs/dependency-licenses.json"))
            inputs.files(rootProject.fileTree("app/src/main/assets/licenses") { include("Go*.txt") })
            inputs.file(rootProject.file("native_build/verification/tls/audit_bridge.py"))
            inputs.property("goExecutable", tlsGoExecutable)
            inputs.property("abi", abi)
            outputs.dir(output)
            doFirst {
                commandLine(tlsPythonExecutable.get(), script.absolutePath,
                    "--ndk", android.ndkDirectory.absolutePath, "--abi", abi,
                    "--go", tlsGoExecutable.get(), "--output", output.get().asFile.absolutePath)
            }
        }
        val staged = layout.buildDirectory.dir("generated/tlsEngine/$variant")
        val stage = tasks.register<Sync>("stage${suffix}TlsEngine") {
            dependsOn(buildGo)
            from(output) { include("liblayanalyzer_tls.so"); into(abi) }
            into(staged)
        }
        android.sourceSets.getByName(variant).jniLibs.srcDir(staged)
        tasks.configureEach { if (name == "merge${suffix}JniLibFolders") dependsOn(stage) }
    }
}

if (enableTlsProbe) {
    mapOf("debug" to "arm64-v8a", "emulator" to "x86_64").forEach { (variant, abi) ->
        android.sourceSets.getByName(variant).java.srcDir("src/tlsProbe/java")
        android.sourceSets.getByName(variant).manifest.srcFile("src/tlsProbe/AndroidManifest.xml")
        val suffix = variant.replaceFirstChar { it.uppercase() }
        val sourceLibrary = tlsProbeLibDir.resolve("$abi/liblayanalyzer_tls_probe.so")
        val stagedLibraries = layout.buildDirectory.dir("generated/tlsProbe/$variant")
        // Sync skips all actions for empty sources, including doFirst. Validate in
        // a dependency so a missing Go build cannot silently produce an ON APK.
        val validateProbe = tasks.register("validate${suffix}TlsProbe") {
            inputs.file(sourceLibrary)
            doLast {
                check(sourceLibrary.isFile) { "Build TLS-003 $abi library before enabling the TLS probe" }
            }
        }
        val stageProbe = tasks.register<Sync>("stage${suffix}TlsProbe") {
            dependsOn(validateProbe)
            from(sourceLibrary) { into(abi) }
            into(stagedLibraries)
        }
        android.sourceSets.getByName(variant).jniLibs.srcDir(stagedLibraries)
        tasks.configureEach {
            if (name == "merge${suffix}JniLibFolders") dependsOn(stageProbe)
        }
    }
}

androidComponents {
    onVariants(selector().all()) { variant ->
        if (variant.buildType == "debug" || variant.buildType == "emulator") {
            // Debuggable builds retain native symbols for useful tombstones.
            // Release variants use the NDK's normal strip step.
            variant.packaging.jniLibs.keepDebugSymbols.add("**/*.so")
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.appcompat)
    implementation("androidx.multidex:multidex:2.0.1")
    implementation(libs.material)

    // Added for Paging and ViewModel
    implementation(libs.androidx.paging.runtime)
    implementation(libs.androidx.paging.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.okhttp)
    implementation(libs.commonmark)

    testImplementation(libs.junit)
    testImplementation("org.json:json:20240303")
    testImplementation(libs.mockwebserver)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
    add("emulatorImplementation", libs.androidx.ui.test.manifest)
}

// NIO-505 capacity matrix: make the per-tier transfer duration configurable from the command
// line (-Pnio505TierSeconds=<seconds>, default 30) without changing any default behaviour.
tasks.withType<Test>().configureEach {
    systemProperty("nio505.tierSeconds", providers.gradleProperty("nio505TierSeconds").getOrElse("30"))
}
