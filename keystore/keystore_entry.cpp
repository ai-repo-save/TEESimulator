// Injection entry point for the legacy keystore interceptor (Android 10/11).
//
// The daemon injects this into the keystore daemon and calls entry(). We install
// the libbinder ioctl hook, register the app-facing keystore service so its
// transactions reach our handler, and start the control server. The profile set
// arrives from the daemon over the control socket; nothing is read from disk here.

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>

#include <functional>

#include "control.h"
// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "ks1"
#include "logging.hpp"

using namespace android;
using TransactionHandler =
    std::function<bool(uint32_t code, const Parcel& data, Parcel* reply, status_t& result)>;

// binder_interceptor.cpp
bool teesim_intercept_service(const sp<IBinder>& service, TransactionHandler handler);
bool teesim_install_binder_hook();
// keystore_router.cpp
extern "C" bool teesim_ks_handle(uint32_t code, const Parcel& data, Parcel* reply, status_t& result);

extern "C" [[gnu::visibility("default")]] bool entry(void* /*handle*/) {
  int api = teesim_android_api();
  LOGI("entry: keystore interceptor loading (api=%d, %s transaction codes)", api,
       api >= 30 ? "Android 11" : "Android 10");
  teesim_control_start();

  if (!teesim_install_binder_hook()) {
    LOGE("entry: failed to install the binder hook");
    return false;
  }
  sp<IBinder> service = defaultServiceManager()->checkService(String16("android.security.keystore"));
  if (service == nullptr) {
    LOGE("entry: android.security.keystore not found");
    return false;
  }
  bool ok = teesim_intercept_service(service, &teesim_ks_handle);
  LOGI("entry: keystore interceptor installed=%d (awaiting config push)", ok);
  return ok;
}
