-keep,allowshrinking class com.example.layanalyzer.NativeEngine { *; }
# Keep the formal TLS ABI even when a particular entry has no current UI caller.
# Unused P0 declarations and debug-only perf exports must be removable by R8.
-keepclassmembers class com.example.layanalyzer.NativeEngine {
    native *** getTlsProxyCapabilities(...);
    native *** startTlsProxy(...);
    native *** stopTlsProxy(...);
    native *** pollTlsProxyEvents(...);
    native *** getTlsProxyStats(...);
    native *** getTlsProxyToken(...);
    native *** generateTlsCaMaterial(...);
    native *** configureTlsSecrets(...);
    native *** projectTlsClientHellos(...);
    native *** getPacketDataSources(...);
    native *** readPacketDataSource(...);
    native *** followTlsStream(...);
    native *** exportTlsFollowStream(...);
}
# Native resolves live callbacks through GetObjectClass + GetMethodID. Keep
# their names and concrete onProgress methods; unused P0 interfaces may shrink.
-keep,allowshrinking interface com.example.layanalyzer.NativeEngine$* { *; }
-keep interface com.example.layanalyzer.NativeEngine$IndexProgressCallback { *; }
-keep interface com.example.layanalyzer.NativeEngine$RtpProgressCallback { *; }
-keepclassmembers class * implements com.example.layanalyzer.NativeEngine$IndexProgressCallback {
    public boolean onProgress(int, long, long);
}
-keepclassmembers class * implements com.example.layanalyzer.NativeEngine$RtpProgressCallback {
    public boolean onProgress(int, int);
}
-keep class com.example.layanalyzer.core.PacketSummary { *; }
-keep class com.example.layanalyzer.capture.Tun2SocksBridge { *; }
-keep interface com.example.layanalyzer.capture.tls.TlsPlatformCallbacks { *; }
-keepclassmembers class * implements com.example.layanalyzer.capture.tls.TlsPlatformCallbacks { public *; }
# JNI FindClass + ThrowNew uses this exact class name and String constructor.
# Kotlin references to the enum constructor do not protect either from R8.
-keep class com.example.layanalyzer.capture.tls.TlsCertificateException {
    public <init>(java.lang.String);
}

# Preserve names and descriptor types for surviving native declarations,
# including future entry points, while allowing unused declarations to shrink.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# AGP 8.4.1's R8 can add discriminator parameters while merging the large
# Compose restart lambdas, exceeding the DEX argument limit (TLS-405).
# Keep optimization local to other classes; these lambdas may still shrink
# and obfuscate. Do not disable R8 for the application.
-keep,allowshrinking,allowobfuscation class com.example.layanalyzer.ui.components.PacketListScreenKt$PacketListScreen$* { *; }
