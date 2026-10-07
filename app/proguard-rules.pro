-keep class com.example.layanalyzer.NativeEngine { *; }
# Every nested interface of NativeEngine is a JNI callback type: the native
# side resolves onProgress through GetObjectClass + GetMethodID, so R8 must not
# rename or strip them.
-keep interface com.example.layanalyzer.NativeEngine$* { *; }
-keep class com.example.layanalyzer.core.PacketSummary { *; }
-keep class com.example.layanalyzer.capture.Tun2SocksBridge { *; }

# Preserve every Java/Kotlin native declaration and the descriptor types used
# at the JNI boundary, including future native entry points.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
