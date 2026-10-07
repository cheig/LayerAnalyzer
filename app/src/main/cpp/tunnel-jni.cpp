#include <jni.h>

#include <android/log.h>
#include <sys/socket.h>
#include <unistd.h>

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

extern "C" {
// Keep the C++ JNI bridge on HEV's C ABI instead of including internal C
// headers. Several upstream public include entries are Unix symlinks and some
// core headers use C-only enum forward declarations.
enum HevLoggerLevel {
    HEV_LOGGER_DEBUG,
    HEV_LOGGER_INFO,
    HEV_LOGGER_WARN,
    HEV_LOGGER_ERROR,
    HEV_LOGGER_UNSET,
};

enum HevSocks5LoggerLevel {
    HEV_SOCKS5_LOGGER_DEBUG,
    HEV_SOCKS5_LOGGER_INFO,
    HEV_SOCKS5_LOGGER_WARN,
    HEV_SOCKS5_LOGGER_ERROR,
    HEV_SOCKS5_LOGGER_UNSET,
};

int hev_config_init_from_str(const unsigned char* config, unsigned int length);
void hev_config_fini();
int hev_config_get_misc_log_level();
const char* hev_config_get_misc_log_file();
int hev_config_get_misc_connect_timeout();
int hev_config_get_misc_tcp_read_write_timeout();
int hev_config_get_misc_udp_read_write_timeout();
int hev_config_get_misc_udp_recv_buffer_size();

int hev_logger_init(HevLoggerLevel level, const char* path);
void hev_logger_fini();
int hev_socks5_logger_init(HevSocks5LoggerLevel level, const char* path);
void hev_socks5_logger_fini();
void hev_socks5_set_connect_timeout(int timeout);
void hev_socks5_set_tcp_timeout(int timeout);
void hev_socks5_set_udp_timeout(int timeout);
void hev_socks5_set_udp_recv_buffer_size(int size);

int hev_task_system_init();
void hev_task_system_fini();
void lwip_init();
int hev_socks5_tunnel_init(int tunFd);
void hev_socks5_tunnel_fini();
int hev_socks5_tunnel_run();
void hev_socks5_tunnel_stop();
void hev_socks5_tunnel_stats(size_t* txPackets, size_t* txBytes,
                             size_t* rxPackets, size_t* rxBytes);
}

namespace {

constexpr char kLogTag[] = "LayAnalyzer-JNI";

struct TunnelState {
    std::mutex mutex;
    std::condition_variable stateChanged;
    std::thread worker;
    bool active = false;
    bool initializationFinished = false;
    bool initialized = false;
    bool engineAvailable = false;
    bool stopRequested = false;
    bool stopSent = false;
    bool stopCallInProgress = false;
};

TunnelState gTunnel;

void logError(const char* message) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "%s", message);
}

void closeFd(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

void signalInitialization(bool initialized) {
    std::lock_guard<std::mutex> lock(gTunnel.mutex);
    gTunnel.initialized = initialized;
    gTunnel.engineAvailable = initialized;
    gTunnel.initializationFinished = true;
    gTunnel.stateChanged.notify_all();
}

void markEngineUnavailableAndWaitForStopCall() {
    std::unique_lock<std::mutex> lock(gTunnel.mutex);
    gTunnel.engineAvailable = false;
    gTunnel.initialized = false;
    gTunnel.stateChanged.notify_all();
    gTunnel.stateChanged.wait(lock, [] { return !gTunnel.stopCallInProgress; });
}

bool consumeStopRequest() {
    std::lock_guard<std::mutex> lock(gTunnel.mutex);
    if (!gTunnel.stopRequested || gTunnel.stopSent) {
        return false;
    }
    gTunnel.stopSent = true;
    return true;
}

// This mirrors hev_socks5_tunnel_main_from_str, but exposes a point after the
// engine's event fd exists. Calling the upstream stop API before that point can
// wait forever when configuration initialization has failed.
int runHevTunnel(const std::string& config, int engineFd) {
    bool configInitialized = false;
    bool loggerInitialized = false;
    bool socksLoggerInitialized = false;
    bool taskSystemInitialized = false;
    bool tunnelInitialized = false;
    HevLoggerLevel logLevel = HEV_LOGGER_ERROR;
    const char* logFile = nullptr;
    int result = -1;

    if (hev_config_init_from_str(
            reinterpret_cast<const unsigned char*>(config.data()),
            static_cast<unsigned int>(config.size())) < 0) {
        signalInitialization(false);
        return -1;
    }
    configInitialized = true;

    logLevel = static_cast<HevLoggerLevel>(hev_config_get_misc_log_level());
    logFile = hev_config_get_misc_log_file();
    if (hev_logger_init(logLevel, logFile) < 0) {
        signalInitialization(false);
        goto cleanup;
    }
    loggerInitialized = true;

    if (hev_socks5_logger_init(static_cast<HevSocks5LoggerLevel>(logLevel), logFile) < 0) {
        signalInitialization(false);
        goto cleanup;
    }
    socksLoggerInitialized = true;

    hev_socks5_set_connect_timeout(hev_config_get_misc_connect_timeout());
    hev_socks5_set_tcp_timeout(hev_config_get_misc_tcp_read_write_timeout());
    hev_socks5_set_udp_timeout(hev_config_get_misc_udp_read_write_timeout());
    hev_socks5_set_udp_recv_buffer_size(hev_config_get_misc_udp_recv_buffer_size());

    if (hev_task_system_init() < 0) {
        signalInitialization(false);
        goto cleanup;
    }
    taskSystemInitialized = true;

    lwip_init();
    if (hev_socks5_tunnel_init(engineFd) < 0) {
        signalInitialization(false);
        goto cleanup;
    }
    tunnelInitialized = true;
    signalInitialization(true);

    if (consumeStopRequest()) {
        hev_socks5_tunnel_stop();
    }

    result = hev_socks5_tunnel_run();

cleanup:
    if (tunnelInitialized) {
        // Do not let another thread call HEV's stop API after its event fd has
        // been destroyed by fini().
        markEngineUnavailableAndWaitForStopCall();
        hev_socks5_tunnel_fini();
    }
    if (socksLoggerInitialized) {
        hev_socks5_logger_fini();
    }
    if (loggerInitialized) {
        hev_logger_fini();
    }
    if (configInitialized) {
        hev_config_fini();
    }
    if (taskSystemInitialized) {
        hev_task_system_fini();
    }
    return result;
}

void runTunnelWorker(std::string config, int engineFd) {
    const int result = runHevTunnel(config, engineFd);
    closeFd(engineFd);

    {
        std::lock_guard<std::mutex> lock(gTunnel.mutex);
        if (!gTunnel.initializationFinished) {
            gTunnel.initializationFinished = true;
            gTunnel.initialized = false;
            gTunnel.engineAvailable = false;
        }
        gTunnel.active = false;
        gTunnel.stateChanged.notify_all();
    }

    if (result != 0) {
        __android_log_print(ANDROID_LOG_WARN, kLogTag, "HEV tunnel exited with status %d.", result);
    }
}

void joinFinishedWorker() {
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(gTunnel.mutex);
        if (gTunnel.worker.joinable() && !gTunnel.active) {
            worker = std::move(gTunnel.worker);
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
}

void stopTunnel();

bool startTunnel(int engineFd, const std::string& config) {
    joinFinishedWorker();

    std::unique_lock<std::mutex> lock(gTunnel.mutex);
    if (gTunnel.active || gTunnel.worker.joinable()) {
        closeFd(engineFd);
        return false;
    }

    gTunnel.active = true;
    gTunnel.initializationFinished = false;
    gTunnel.initialized = false;
    gTunnel.engineAvailable = false;
    gTunnel.stopRequested = false;
    gTunnel.stopSent = false;
    gTunnel.stopCallInProgress = false;

    try {
        gTunnel.worker = std::thread(runTunnelWorker, config, engineFd);
    } catch (...) {
        gTunnel.active = false;
        closeFd(engineFd);
        return false;
    }

    gTunnel.stateChanged.wait(lock, [] { return gTunnel.initializationFinished; });
    if (gTunnel.initialized) {
        return true;
    }

    lock.unlock();
    stopTunnel();
    return false;
}

void stopTunnel() {
    bool sendStop = false;
    {
        std::unique_lock<std::mutex> lock(gTunnel.mutex);
        if (!gTunnel.worker.joinable()) {
            return;
        }

        gTunnel.stopRequested = true;
        if (!gTunnel.initializationFinished) {
            gTunnel.stateChanged.wait(lock, [] { return gTunnel.initializationFinished; });
        }
        if (gTunnel.active && gTunnel.engineAvailable && !gTunnel.stopSent) {
            gTunnel.stopSent = true;
            gTunnel.stopCallInProgress = true;
            sendStop = true;
        }
    }

    if (sendStop) {
        hev_socks5_tunnel_stop();
        std::lock_guard<std::mutex> lock(gTunnel.mutex);
        gTunnel.stopCallInProgress = false;
        gTunnel.stateChanged.notify_all();
    }

    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(gTunnel.mutex);
        if (gTunnel.worker.joinable()) {
            worker = std::move(gTunnel.worker);
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
}

bool isTunnelRunning() {
    std::lock_guard<std::mutex> lock(gTunnel.mutex);
    return gTunnel.active && gTunnel.engineAvailable;
}

}  // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_example_layanalyzer_capture_Tun2SocksBridge_createPacketSocketPair(
    JNIEnv* env,
    jobject /* thiz */
) {
    int fds[2] = { -1, -1 };
    const int socketFlags = SOCK_NONBLOCK | SOCK_CLOEXEC;
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | socketFlags, 0, fds) != 0 &&
        socketpair(AF_UNIX, SOCK_DGRAM | socketFlags, 0, fds) != 0) {
        logError("Unable to create packet relay socket pair.");
        return nullptr;
    }

    jintArray result = env->NewIntArray(2);
    if (result == nullptr) {
        closeFd(fds[0]);
        closeFd(fds[1]);
        return nullptr;
    }

    const jint values[2] = { fds[0], fds[1] };
    env->SetIntArrayRegion(result, 0, 2, values);
    return result;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_capture_Tun2SocksBridge_start(
    JNIEnv* env,
    jobject /* thiz */,
    jint engineFd,
    jstring config
) {
    if (engineFd < 0 || config == nullptr) {
        closeFd(engineFd);
        return JNI_FALSE;
    }

    const char* configChars = env->GetStringUTFChars(config, nullptr);
    if (configChars == nullptr) {
        closeFd(engineFd);
        return JNI_FALSE;
    }

    const std::string configCopy(configChars);
    env->ReleaseStringUTFChars(config, configChars);
    if (configCopy.empty()) {
        closeFd(engineFd);
        return JNI_FALSE;
    }

    return startTunnel(engineFd, configCopy) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_layanalyzer_capture_Tun2SocksBridge_stop(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    stopTunnel();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_layanalyzer_capture_Tun2SocksBridge_isRunning(
    JNIEnv* /* env */,
    jobject /* thiz */
) {
    return isTunnelRunning() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_example_layanalyzer_capture_Tun2SocksBridge_getStats(
    JNIEnv* env,
    jobject /* thiz */
) {
    size_t txPackets = 0;
    size_t txBytes = 0;
    size_t rxPackets = 0;
    size_t rxBytes = 0;
    {
        // Keep fini() from tearing down the engine while the counters are read.
        std::lock_guard<std::mutex> lock(gTunnel.mutex);
        if (gTunnel.active && gTunnel.engineAvailable) {
            hev_socks5_tunnel_stats(&txPackets, &txBytes, &rxPackets, &rxBytes);
        }
    }

    const jlong values[4] = {
        static_cast<jlong>(txPackets),
        static_cast<jlong>(txBytes),
        static_cast<jlong>(rxPackets),
        static_cast<jlong>(rxBytes),
    };
    jlongArray result = env->NewLongArray(4);
    if (result != nullptr) {
        env->SetLongArrayRegion(result, 0, 4, values);
    }
    return result;
}
