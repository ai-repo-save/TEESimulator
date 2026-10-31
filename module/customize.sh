# Runs at install time under Magisk, KernelSU, or APatch.

# The interceptor is a 64-bit library injected into the keystore daemon. This build ships arm64-v8a
# only, so any other device would install a module with no native libraries: refuse it here.
if [ "$ARCH" != "arm64" ]; then
  abort "! TEESimulator builds arm64-v8a only; this device reports ARCH=$ARCH"
fi

# TrickyStore intercepts the same keystore path; running both would double-hook it. Disable it via
# its manager's marker (kept, not deleted, so removing us lets the user re-enable it).
for ts in /data/adb/modules/tricky_store /data/adb/modules_update/tricky_store; do
  if [ -d "$ts" ] && [ ! -f "$ts/disable" ]; then
    ui_print "- Disabling TrickyStore (it hooks the same keystore path)"
    touch "$ts/disable"
  fi
done

# Seed the configuration on first install without clobbering existing files.
mkdir -p /data/adb/teesim
# Adopt a keybox the user already set up for TrickyStore when we have none of our own.
if [ ! -f /data/adb/teesim/keybox.xml ] && [ -f /data/adb/tricky_store/keybox.xml ]; then
  ui_print "- Adopting the keybox from TrickyStore"
  cp /data/adb/tricky_store/keybox.xml /data/adb/teesim/keybox.xml
fi
if [ ! -f /data/adb/teesim/config.json ]; then
  cp "$MODPATH/config.default.json" /data/adb/teesim/config.json
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/daemon" 0 0 0755
for f in inject teesim-uds; do
  [ -f "$MODPATH/arm64-v8a/$f" ] && set_perm "$MODPATH/arm64-v8a/$f" 0 0 0755
done
