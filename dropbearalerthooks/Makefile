include theos/makefiles/common.mk

TWEAK_NAME = DropbearAlert

DropbearAlert_FILES = /mnt/d/codes/dropbearalert/dropbearalerthooks/DropbearAlert.xm
DropbearAlert_FRAMEWORKS = CydiaSubstrate Foundation UIKit
DropbearAlert_LDFLAGS = -Wl,-segalign,4000

export ARCHS = armv7 arm64
DropbearAlert_ARCHS = armv7 arm64

include $(THEOS_MAKE_PATH)/tweak.mk
	
all::
	