#
# Generated by the Apple Project Builder.
#
# NOTE: Do NOT change this file -- Project Builder maintains it.
#
# Put all of your customizations in files called Makefile.preamble
# and Makefile.postamble (both optional), and Makefile will include them.
#

NAME = GPGME

PROJECTVERSION = 2.8
PROJECT_TYPE = Framework

CLASSES = GPGContext.m GPGData.m GPGEngine.m GPGExceptions.m GPGKey.m\
          GPGObject.m GPGRecipients.m GPGTrustItem.m

HFILES = GPG.h GPGContext.h GPGData.h GPGDefines.h GPGEngine.h\
         GPGExceptions.h GPGInternals.h GPGKey.h GPGObject.h\
         GPGRecipients.h GPGTrustItem.h

OTHERSRCS = h.template m.template Makefile Makefile.postamble\
            Makefile.preamble

MAKEFILEDIR = $(MAKEFILEPATH)/pb_makefiles
CURRENTLY_ACTIVE_VERSION = YES
DEPLOY_WITH_VERSION_NAME = 0.2.3
CODE_GEN_STYLE = DYNAMIC
MAKEFILE = framework.make
NEXTSTEP_INSTALLDIR = /Library/Frameworks
WINDOWS_INSTALLDIR = /Library/Frameworks
PDO_UNIX_INSTALLDIR = /Library/Frameworks
LIBS = -lgpgme
DEBUG_LIBS = $(LIBS)
PROF_LIBS = $(LIBS)


HEADER_PATHS = -I/usr/local/include
LIBRARY_PATHS = -L/usr/local/lib
FRAMEWORKS = -framework Foundation
PUBLIC_HEADERS = GPG.h GPGContext.h GPGDefines.h GPGExceptions.h\
                 GPGKey.h GPGObject.h GPGRecipients.h GPGTrustItem.h\
                 GPGEngine.h GPGData.h



NEXTSTEP_BUILD_OUTPUT_DIR = $(LOCAL_DEVELOPER_DIR)/Builds/$(USER)/$(NAME)

NEXTSTEP_OBJCPLUS_COMPILER = /usr/bin/cc
WINDOWS_OBJCPLUS_COMPILER = $(DEVDIR)/gcc
PDO_UNIX_OBJCPLUS_COMPILER = $(NEXTDEV_BIN)/gcc
NEXTSTEP_JAVA_COMPILER = /usr/bin/javac
WINDOWS_JAVA_COMPILER = $(JDKBINDIR)/javac.exe
PDO_UNIX_JAVA_COMPILER = $(JDKBINDIR)/javac

include $(MAKEFILEDIR)/platform.make

-include Makefile.preamble

include $(MAKEFILEDIR)/$(MAKEFILE)

-include Makefile.postamble

-include Makefile.dependencies
