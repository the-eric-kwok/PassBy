# Target iOS 9+ 64-bit Devices; use the iOS 16.5 SDK
TARGET = iphone:clang:16.5:9.0

INSTALL_TARGET_PROCESSES = SpringBoard

FINALPACKAGE = 1
# DEBUG = 1
export ARCHS = arm64 arm64e
export ADDITIONAL_CFLAGS = -O3

include $(THEOS)/makefiles/common.mk


TWEAK_NAME = PassBy
PassBy_FILES = Tweak.xm
PassBy_CFLAGS = -fobjc-arc

PassBy_FRAMEWORKS = UIKit
PassBy_PRIVATE_FRAMEWORKS = SpringBoard SpringBoardFoundation BluetoothManager BatteryCenter MobileWiFi

include $(THEOS_MAKE_PATH)/tweak.mk


# `killall SpringBoard` (without -9) lets SpringBoard shut down cleanly,
# which avoids wedged state during the respring that follows an install.
after-install::
	install.exec "killall SpringBoard"


SUBPROJECTS += passbyprefs
include $(THEOS_MAKE_PATH)/aggregate.mk

# Convenience targets for the two package flavours:
#   make rootful-package   -> traditional rootful jailbreaks (arm64/arm64e)
#   make rootless-package  -> rootless jailbreaks such as Dopamine/Fugu15
# Rootless targets A12+ jailbreaks whose SpringBoard/Settings are arm64e
# processes, so both slices must be present; an arm64-only dylib is silently
# rejected by arm64e hosts.
rootful-package::
	$(MAKE) clean
	$(MAKE)
	$(MAKE) package

rootless-package::
	$(MAKE) clean
	$(MAKE) ARCHS="arm64 arm64e"
	env -u _THEOS_TOP_INVOCATION_DONE $(MAKE) stage THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e"
	env -u _THEOS_TOP_INVOCATION_DONE $(MAKE) package THEOS_PACKAGE_SCHEME=rootless ARCHS="arm64 arm64e" THEOS_PACKAGE_DIR=packages/rootless
