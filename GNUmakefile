#
# If GNUSTEP_SYSTEM_ROOT is equal to nothing then include 
# ProjectBuilder makefile named Makefile else use this 
# GNUstep makefile.
# We need to do this, because On MacOS X Server 1.x (Rhapsody),
# GNUmakefile are also used by the make system, and have
# priority over Makefile, whereas Makefile MUST be used.
#
# Thanks to Damian Steer <shellac@shellac.freeserve.co.uk>
#

ifeq ($(GNUSTEP_SYSTEM_ROOT),)
  include Makefile
else

FRAMEWORK_NAME = GPGME
CURRENT_VERSION_NAME = 0.3.4

GPGME_OBJC_FILES = GPGContext.m GPGData.m GPGEngine.m GPGExceptions.m GPGKey.m\
           GPGObject.m GPGRecipients.m GPGTrustItem.m GPGPrettyInfo.m\
		   LocalizableStrings.m

GPGME_HEADER_FILES=GPGContext.h GPGData.h GPGDefines.h GPGEngine.h\
          GPGExceptions.h GPGInternals.h GPGKey.h GPGME.h GPGObject.h\
          GPGRecipients.h GPGTrustItem.h GPGPrettyInfo.h LocalizableStrings.h

ADDITIONAL_OBJCFLAGS += -I../

include $(GNUSTEP_MAKEFILES)/common.make

-include Makefile.preamble

include $(GNUSTEP_MAKEFILES)/framework.make

-include Makefile.postamble

-include Makefile.dependencies

endif
