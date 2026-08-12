# ZygoteNextProbe

检测 Android 17 `zygote_next` native isolated service 的 mount namespace 和 mount
propagation 状态的 PoC。本项目不是通用 root 检测器。

经典 zygote 路径会创建 mount namespace，并对 `/` 执行 `MS_SLAVE | MS_REC`。因此
普通 app 的根挂载通常显示为：

```text
master:1
```

这里的数字是 mount propagation peer group ID，实际设备上不保证一定是 `1`。
`shared:N`/`master:N` 描述传播关系，不能单独证明两个进程是同一个 mount
namespace。PID 1 的根挂载在本设备上显示为：

```text
shared:1
```

当前目标的 `zygote_next` native child 是由 init 启动的 `zygote_next` 直接 fork 出来，
相关 spawn/re-initialization 路径没有执行经典 zygote 的 mount namespace 初始化。因此
本设备上的 isolated child 显示 `shared:1`，并且通过 root shell 额外确认它与 PID 1
使用同一个 mount namespace。APK 本身不能读取 `/proc/1/ns/mnt`，所以 APK 内部把
`shared:N` 称为 global-view signature，而不是仅凭这一字段声称 namespace 相等。

本次设备的 root-side 对照结果是：

```text
/proc/1/ns/mnt                    mnt:[4026531841]
zygote_next isolated child ns     mnt:[4026531841]
```

两者的 `/proc/*/mountinfo` 也一致。这个 namespace 相等结论是本次设备的外部验证，
不是普通 APK 权限下必然可复现的检查。

## 探针路径

Manifest 中的 service 同时声明：

```xml
android:isolatedProcess="true"
android:nativeService="true"
```

调用链如下：

```text
MainActivity (zygote64)
  -> bindIsolatedService()
  -> AMS 选择 zygote_next
  -> zygote_next fork()
  -> 从 APK 加载 libmain.so
  -> ANativeService_onCreate()
  -> AIDL getResult()
  -> MainActivity 对比两边的 mountinfo
```

普通主进程是对照组。当前设备的典型结果是：

```text
self      master:1
isolated  shared:1
```

`CONTRAST` 表示 native isolated service 呈现出与经典 app 不同的 shared/global-view
传播特征。若要证明它就是 PID 1 namespace，需要额外的特权对照；本设备已经完成该
对照。

`ROOT LEAK` 则表示该进程还能在自己的 mountinfo 中看到 ZN、Zygisk、Sui、LSP、Magisk、
`/data/adb/` 或 `/debug_ramdisk` 相关挂载。匹配不区分大小写，结果会
同时显示命中标签、mountpoint、mount root 和 source。这里检查的是挂载记录，不是
进程列表；没有某个标签不代表对应软件或守护进程不存在。

本次实测中，普通主进程没有发现 root marker，而 native isolated service 在自己的
`/proc/self/mountinfo` 中看到：

```text
ADB: /data/adb/modules/meta-overlayfs/mnt [ext4; root=/; source=/dev/block/loop53]
```

同一个 APK 的主进程看不到该挂载，isolated 进程却能看到，说明当前设备上这条
`zygote_next` 路径仍然能看到 init-derived mount view 中的模块挂载。

## Native 实现

`probe.cpp` 不依赖 ART。`zygote_next` 加载 `libmain.so` 后调用
`ANativeService_onCreate()`，探针再通过 `dlsym()` 解析 `libbinder_ndk.so`：

- `AIBinder_Class_define`
- `AIBinder_new`
- `AParcel_writeInt32`
- `AParcel_writeString`

AIDL 的 `getResult()` 是 transaction code 1。回复内容按 Binder Java 客户端预期写成
`NO_EXCEPTION` 的 `int32`，后跟一个 `String`。传输格式为：

```text
pid|isolated|mntNsSelf|mntNsInit|proc1Readable|mntNsZygoteNext|zygoteNext|selfPropagation|zygoteNextProps|rootMarkers
```

isolated uid 通常会被 `ptrace_may_access` 阻止读取 `/proc/1`，所以
`mntNsInit=0`、`proc1Readable=false` 是正常现象。`shared:N`/`master:N` 是传播信号，
namespace 相等需要特权对照或其他独立证据。

Native 侧还会动态读取完整的 `/proc/self/mountinfo`，逐行输出到 logcat。不能用
固定缓冲区或 `st_size` 读取，因为 procfs 文件的 `st_size` 通常为 0，而且现代设备
的 mountinfo 很容易超过 16 KiB。

```bash
adb logcat -s ZygoteNextProbe
```

## AOSP 引用

以下链接固定到 Android 17 首个公开 tag `android-17.0.0_r1`：

- 经典 zygote 创建 mount namespace，并把根挂载改为 slave：
  [`com_android_internal_os_Zygote.cpp:2317`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2317)、
  [`:2324`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2324)
- app specialization 期间进入 app mount namespace：
  [`com_android_internal_os_Zygote.cpp:577`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#577)、
  [`:1953`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#1953)
- `init` 以 root 身份启动 `zygote_next`：
  [`zygote_next.rc:1`](https://android.googlesource.com/platform/system/zygote/+/refs/tags/android-17.0.0_r1/zygote/zygote_next.rc#1)
- AMS 给 native isolated service 设置 native process policy，`Process.start()` 据此选择
  `NATIVE_ZYGOTE_PROCESS`：
  [`ActiveServices.java:6357`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/am/ActiveServices.java#6357)、
  [`Process.java:795`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/core/java/android/os/Process.java#795)
- `zygote_next` 处理 spawn 请求时直接调用 `fork()`，随后进入 child re-initialization；
  这些函数本身没有经典 zygote 的 `CLONE_NEWNS`/`MS_SLAVE` 初始化：
  [`server.rs:910`](https://android.googlesource.com/platform/system/zygote/+/refs/tags/android-17.0.0_r1/zygote/src/server.rs#910)、
  [`server.rs:1017`](https://android.googlesource.com/platform/system/zygote/+/refs/tags/android-17.0.0_r1/zygote/src/server.rs#1017)
- child re-initialization 在设置 seccomp 后调用 `setresuid()`，随后才覆盖 capabilities；
  这是观察 child credential transition 时的关键顺序：
  [`child_process.rs:124`](https://android.googlesource.com/platform/system/zygote/+/refs/tags/android-17.0.0_r1/zygote/src/child_process.rs#124)
- framework 默认加载 `libmain.so` 并查找 `ANativeService_onCreate`，Rust native thread
  完成 `dlopen`、符号解析和入口调用：
  [`NativeApplicationThreadWrapper.java:85`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/services/core/java/com/android/server/am/NativeApplicationThreadWrapper.java#85)、
  [`native_activity_thread.rs:124`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-17.0.0_r1/libs/native_activity_thread/src/native_activity_thread.rs#124)

感谢 [AlexLiuDev233](https://github.com/AlexLiuDev233) 原神佬喵
