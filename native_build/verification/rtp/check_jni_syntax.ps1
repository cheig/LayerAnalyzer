<#
.SYNOPSIS
    用 MSVC 的前端（cl /Zs）对 JNI 翻译单元做纯语法检查。

.DESCRIPTION
    为什么需要这个脚本：本仓库的 Android 侧编译需要 NDK + `app/src/main/cpp/libs/`
    下预编译的 Wireshark 库，两者都是单独分发、不入库的（CONTRIBUTING.md），
    所以在只有 MSVC 的开发机上，改 `jni/RtpJni.cpp` 这类文件既编不进 host 单测
    （它依赖 epan），也过不了 Gradle 的 native 构建。`cl /Zs` 只跑到前端：能抓出
    语法错误、拼错的标识符、类型不匹配、参数个数不对、用了不存在的成员——这类错误
    正是 JNI 黏合代码最常见的。

    **它能证明什么**：这些翻译单元的前端解析通过，且在 `/W4` 下没有本脚本自己产生的
    告警。**它不能证明什么**：不生成目标文件、不做链接，所以看不到符号缺失、ABI 不一致；
    真实的 Android 构建（clang + NDK + 真 epan 头文件）仍必须在有 NDK 的机器上跑。

    为了让 Android 平台的头部能被桌面编译器解析，脚本会在 `%TEMP%\rtp_jni_syntax\shims`
    下生成一组**只用于解析**的替身头文件（Bionic 的 <android/log.h>、POSIX 的
    <sys/socket.h> 等，以及一个强制包含的 `msvc_forced.h`），并把 `include/`、
    `include/glib-2.0`、`include/wireshark` 和 JDK 的 `jni.h` 一起加进包含路径。
    这些替身不入库、不参与任何构建，只在本次检查的进程里存在。

    两个容易踩的坑，脚本已经处理：
      * `/utf-8` 不能省。仓库源码是 UTF-8 而 MSVC 默认按系统代码页（936/GBK）解析，
        中文注释里会出现「尾字节 0x5C」把换行吃掉，于是文件后面的 `#ifdef` 整段错位，
        报出来的却是 `fatal error C1019: unexpected #else`。host_tests/CMakeLists.txt
        对同一条坑加了 /utf-8。
      * `-DHAVE_SSIZE_T=1`。`include/gcrypt.h`（`typedef long ssize_t`）与
        `include/wireshark/ws_posix_compat.h`（`typedef int64_t ssize_t`）在 _WIN32 下
        会互相冲突；Android 上 gcrypt 那条分支不成立，所以只有桌面检查需要绕开。
      * `-DSOCKET=int`。c-ares 的 `ares.h` 在 `_WIN32 && !WATT32` 下用 winsock 的
        `SOCKET`，而它的 `ares_build.h` 是给 Android 生成的、不包含 winsock2.h。

.PARAMETER File
    要检查的源文件，相对于 `app/src/main/cpp/`。默认只检查 `layanalyzer/jni/RtpJni.cpp`。

.PARAMETER Clean
    检查前删除替身目录（正常不需要）。

.EXAMPLE
    .\check_jni_syntax.ps1

.EXAMPLE
    .\check_jni_syntax.ps1 -File layanalyzer/jni/RtpJni.cpp,layanalyzer/jni/ConfigurationJni.cpp
#>
[CmdletBinding()]
param(
    [string[]] $File = @('layanalyzer/jni/RtpJni.cpp'),
    [switch] $Clean
)

$ErrorActionPreference = 'Stop'
if (Test-Path Variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$CppRoot = Join-Path $RepoRoot 'app\src\main\cpp'
$ShimDir = Join-Path $env:TEMP 'rtp_jni_syntax\shims'

function Write-Step {
    param([string] $Message)
    Write-Host ("[check_jni_syntax] {0}" -f $Message)
}

if (-not (Test-Path -LiteralPath (Join-Path $CppRoot 'layanalyzer\internal\Common.h'))) {
    throw "找不到 native 源码根：$CppRoot"
}

# ---- 1. 工具链：cl 优先，其次 vcvars64.bat ---------------------------------
$cl = Get-Command -Name cl -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
$vcvars64 = $null
if (-not $cl) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        Write-Host '找不到 cl，也找不到 vswhere.exe：本机没有 MSVC。' -ForegroundColor Yellow
        Write-Host '安装「Visual Studio Build Tools」并在工作负载里勾选「使用 C++ 的桌面开发」即可。'
        exit 1
    }
    $vsRoot = (& $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1)
    if ($vsRoot) {
        $vcvars64 = Join-Path ($vsRoot.Trim()) 'VC\Auxiliary\Build\vcvars64.bat'
    }
    if (-not $vcvars64 -or -not (Test-Path -LiteralPath $vcvars64)) {
        Write-Host 'vswhere 没有给出可用的 vcvars64.bat：本机没有 MSVC。' -ForegroundColor Yellow
        exit 1
    }
}

# ---- 2. JDK 的 jni.h：Common.h 无条件包含 <jni.h> ---------------------------
$jdkHome = $null
foreach ($candidate in @($env:JAVA_HOME)) {
    if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'include\jni.h'))) {
        $jdkHome = $candidate
        break
    }
}
if (-not $jdkHome) {
    $java = Get-Command -Name java -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($java) {
        # …\<jdk>\bin\java.exe -> …\<jdk>
        $home = Split-Path -Parent (Split-Path -Parent $java.Source)
        if (Test-Path -LiteralPath (Join-Path $home 'include\jni.h')) { $jdkHome = $home }
    }
}
if (-not $jdkHome) {
    Write-Host '找不到 JDK 的 include\jni.h（Common.h 无条件包含 <jni.h>）。' -ForegroundColor Yellow
    Write-Host '设置 JAVA_HOME 或把 java 放进 PATH 后重试。'
    exit 1
}
Write-Step ("JDK: {0}" -f $jdkHome)

# ---- 3. 替身头文件（只在本次检查里存在，不入库）-----------------------------
if ($Clean -and (Test-Path -LiteralPath $ShimDir)) {
    Remove-Item -LiteralPath $ShimDir -Recurse -Force
}
foreach ($sub in @('', 'sys', 'netinet', 'arpa', 'android')) {
    $dir = if ($sub) { Join-Path $ShimDir $sub } else { $ShimDir }
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
}

$shims = @{
    'msvc_forced.h' = @'
/* Parse-only forced include. Never linked, never shipped: on Android these
   declarations come from Bionic and winsock2.h, and the desktop compiler has
   neither. The shapes only have to be consistent enough for cl's front end to
   parse our own code. */
#ifndef MSVC_FORCED_SHIM
#define MSVC_FORCED_SHIM
typedef long ssize_t;
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#endif
'@
    'alloca.h' = @'
#ifndef MSVC_ALLOCA_SHIM
#define MSVC_ALLOCA_SHIM
#include <malloc.h>
#define alloca _alloca
#endif
'@
    'dirent.h' = @'
#ifndef MSVC_DIRENT_SHIM
#define MSVC_DIRENT_SHIM
typedef struct __dirstream DIR;
struct dirent {
  unsigned long d_ino;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[256];
};
DIR *opendir(const char *);
struct dirent *readdir(DIR *);
int closedir(DIR *);
int dirfd(DIR *);
#endif
'@
    'pthread.h' = @'
#ifndef MSVC_PTHREAD_SHIM
#define MSVC_PTHREAD_SHIM
#include <time.h>
typedef unsigned long pthread_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;
typedef union { char __opaque[64]; } pthread_mutex_t;
typedef union { char __opaque[64]; } pthread_cond_t;
typedef union { char __opaque[64]; } pthread_attr_t;
typedef union { char __opaque[64]; } pthread_mutexattr_t;
typedef union { char __opaque[64]; } pthread_condattr_t;
typedef union { char __opaque[8]; } pthread_rwlock_t;
#define PTHREAD_MUTEX_INITIALIZER { { 0 } }
#define PTHREAD_COND_INITIALIZER { { 0 } }
#define PTHREAD_ONCE_INIT 0
#endif
'@
    'sys\time.h' = @'
#ifndef MSVC_SYS_TIME_SHIM
#define MSVC_SYS_TIME_SHIM
#include <time.h>
struct timeval { long tv_sec; long tv_usec; };
#endif
'@
    'sys\socket.h' = @'
#ifndef MSVC_SYS_SOCKET_SHIM
#define MSVC_SYS_SOCKET_SHIM
#include <stddef.h>
typedef unsigned int socklen_t;
typedef unsigned short sa_family_t;
struct sockaddr { sa_family_t sa_family; char sa_data[14]; };
struct sockaddr_storage { sa_family_t ss_family; char __pad[126]; };
struct sockaddr_in {
  sa_family_t sin_family; unsigned short sin_port;
  unsigned int sin_addr; char __pad[8];
};
struct sockaddr_in6 {
  sa_family_t sin6_family; unsigned short sin6_port;
  unsigned int sin6_flowinfo; unsigned char sin6_addr[16];
  unsigned int sin6_scope_id;
};
struct addrinfo;
#define AF_UNSPEC 0
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 0xffff
#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
#endif
'@
    'sys\select.h' = @'
#ifndef MSVC_SYS_SELECT_SHIM
#define MSVC_SYS_SELECT_SHIM
#include <sys/time.h>
typedef unsigned long fd_mask;
#define FD_SETSIZE 1024
typedef struct { fd_mask fds_bits[FD_SETSIZE / (8 * sizeof(fd_mask))]; } fd_set;
#define FD_ZERO(s) ((void)0)
#define FD_SET(f, s) ((void)0)
#define FD_ISSET(f, s) 0
#endif
'@
    'netinet\in.h' = @'
#ifndef MSVC_NETINET_IN_SHIM
#define MSVC_NETINET_IN_SHIM
#include <sys/socket.h>
typedef unsigned short in_port_t;
typedef unsigned int in_addr_t;
struct in_addr { in_addr_t s_addr; };
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#endif
'@
    'arpa\inet.h' = @'
#ifndef MSVC_ARPA_INET_SHIM
#define MSVC_ARPA_INET_SHIM
#include <netinet/in.h>
#endif
'@
    'netdb.h' = @'
#ifndef MSVC_NETDB_SHIM
#define MSVC_NETDB_SHIM
#include <sys/socket.h>
struct hostent {
  char *h_name; char **h_aliases; int h_addrtype;
  int h_length; char **h_addr_list;
};
struct addrinfo {
  int ai_flags; int ai_family; int ai_socktype; int ai_protocol;
  size_t ai_addrlen; struct sockaddr *ai_addr; char *ai_canonname;
  struct addrinfo *ai_next;
};
#define EAI_NONAME (-2)
#define NI_NUMERICHOST 1
#define NI_NAMEREQD 4
#endif
'@
    'poll.h' = @'
#ifndef MSVC_POLL_SHIM
#define MSVC_POLL_SHIM
struct pollfd { int fd; short events; short revents; };
typedef unsigned long nfds_t;
#define POLLIN 0x001
#define POLLOUT 0x004
#endif
'@
    'android\log.h' = @'
#ifndef MSVC_ANDROID_LOG_SHIM
#define MSVC_ANDROID_LOG_SHIM
#ifdef __cplusplus
extern "C" {
#endif
enum android_LogPriority {
  ANDROID_LOG_UNKNOWN = 0, ANDROID_LOG_DEFAULT, ANDROID_LOG_VERBOSE,
  ANDROID_LOG_DEBUG, ANDROID_LOG_INFO, ANDROID_LOG_WARN, ANDROID_LOG_ERROR,
  ANDROID_LOG_FATAL, ANDROID_LOG_SILENT
};
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
int __android_log_write(int prio, const char *tag, const char *text);
#ifdef __cplusplus
}
#endif
#endif
'@
}

foreach ($name in $shims.Keys) {
    # ASCII 内容，用 UTF8(no BOM) 写：cl 读到 BOM 会把第一行当垃圾。
    [System.IO.File]::WriteAllText((Join-Path $ShimDir $name), $shims[$name],
        (New-Object System.Text.UTF8Encoding($false)))
}
Write-Step ("替身头文件：{0}" -f $ShimDir)

# ---- 4. 逐个文件跑前端 -----------------------------------------------------
$includeArgs = @(
    "-I$CppRoot"
    "-I$CppRoot\include"
    "-I$CppRoot\include\glib-2.0"
    "-I$CppRoot\include\wireshark"
    "-I$ShimDir"
    "-I$jdkHome\include"
    "-I$jdkHome\include\win32"
)

$failed = 0
foreach ($relative in $File) {
    $source = Join-Path $CppRoot $relative
    if (-not (Test-Path -LiteralPath $source)) {
        Write-Host ("找不到源文件：{0}" -f $relative) -ForegroundColor Yellow
        $failed++
        continue
    }

    $arguments = @(
        '/nologo', '/Zs', '/utf-8', '/std:c++17', '/EHsc', '/W4'
        '/DLA_PERF_SCAN=1', '/DHAVE_SSIZE_T=1', '/DSOCKET=int'
        '/FI', 'msvc_forced.h'
    ) + $includeArgs + @($source)

    $quoted = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $command = if ($vcvars64) {
        'call "{0}" >nul 2>&1 && cl {1}' -f $vcvars64, $quoted
    } else {
        'cl {0}' -f $quoted
    }

    Write-Step ("cl /Zs {0}" -f $relative)
    $output = & cmd.exe /c $command 2>&1
    $output | Where-Object { $_ -match 'error' } | ForEach-Object { Write-Host $_ }

    $errors = @($output | Where-Object { $_ -match ':\s*error ' })
    if ($errors.Count -gt 0) {
        Write-Host ("{0}：{1} 个错误" -f $relative, $errors.Count) -ForegroundColor Yellow
        $failed++
    } else {
        Write-Host ("{0}：前端解析通过（没有 error）" -f $relative) -ForegroundColor Green
    }
}

if ($failed -gt 0) {
    Write-Host ''
    Write-Host ("{0} 个文件没通过。" -f $failed) -ForegroundColor Yellow
    exit 1
}
Write-Host ''
Write-Host '全部通过。注意：这只证明前端解析通过，不代表能链接或能在 Android 上编过。' -ForegroundColor Green
exit 0
