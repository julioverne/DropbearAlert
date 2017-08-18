include theos/makefiles/common.mk

TWEAK_NAME = libDropblearAlert

libDropblearAlert_FILES = /mnt/d/codes/dropbearalert/dropbearalertlib/libDropblearAlert.xm
libDropblearAlert_FRAMEWORKS = CydiaSubstrate Foundation UIKit
libDropblearAlert_LDFLAGS = -Wl,-segalign,4000

export ARCHS = armv7 arm64
libDropblearAlert_ARCHS = armv7 arm64

include $(THEOS_MAKE_PATH)/tweak.mk
	
all::
	