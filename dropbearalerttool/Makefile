include theos/makefiles/common.mk

TOOL_NAME = DropbearAlertTool
DropbearAlertTool_FILES = /mnt/d/codes/dropbearalert/dropbearalerttool/main.mm

DropbearAlertTool_FRAMEWORKS = UIKit
DropbearAlertTool_ARCHS = armv7 arm64
export ARCHS = armv7 arm64
DropbearAlertTool_CFLAGS = -fobjc-arc
DropbearAlertTool_CODESIGN_FLAGS="-Sen.plist"

include $(THEOS_MAKE_PATH)/tool.mk

all::
