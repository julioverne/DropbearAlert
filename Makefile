include theos/makefiles/common.mk

SUBPROJECTS += dropbearalertapp
SUBPROJECTS += dropbearalerthooks
SUBPROJECTS += dropbearalertlib
SUBPROJECTS += dropbearalerttool

include $(THEOS_MAKE_PATH)/aggregate.mk

all::
	
