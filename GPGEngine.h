//
//  GPGEngine.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001 Mac GPG Project.
//  
//  This code is free software; you can redistribute it and/or modify it under
//  the terms of the GNU General Public License as published by the Free
//  Software Foundation; either version 2 of the License, or any later version.
//  
//  This code is distributed in the hope that it will be useful, but WITHOUT ANY
//  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
//  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
//  details.
//  
//  For a copy of the GNU General Public License, visit <http://www.gnu.org/> or
//  write to the Free Software Foundation, Inc., 59 Temple Place--Suite 330,
//  Boston, MA 02111-1307, USA.
//  
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx>
//

#import <GPGME/GPGDefines.h>


@class NSString;


typedef enum {
    GPGErrorEOF              = -1,
    GPGErrorNoError          = 0,
    GPGErrorGeneralError     = 1,
    GPGErrorOutOfCore        = 2,
    GPGErrorInvalidValue     = 3,
    GPGErrorBusy             = 4,
    GPGErrorNoRequest        = 5,
    GPGErrorExecError        = 6,
    GPGErrorTooManyProcs     = 7,
    GPGErrorPipeError        = 8,
    GPGErrorNoRecipients     = 9,
    GPGErrorNoData           = 10,
    GPGErrorConflict         = 11,
    GPGErrorNotImplemented   = 12,
    GPGErrorReadError        = 13,
    GPGErrorWriteError       = 14,
    GPGErrorInvalidType      = 15,
    GPGErrorInvalidMode      = 16,
    GPGErrorFileError        = 17, /*"errno is set in this case"*/
    GPGErrorDecryptionFailed = 18,
    GPGErrorNoPassphrase     = 19,
    GPGErrorCanceled         = 20,
    GPGErrorInvalidKey       = 21,
    GPGErrorInvalidEngine    = 22
} GPGError;


/*"
 * Checks that the version of the library is at minimum the requested one
 * and returns the version string; returns nil if the condition is not
 * met. If requiredVersion is nil, no check is done and
 * the version string is simply returned.
 *
 * It is a pretty good idea to run this function (or #GPGCheckEngine() or
 * #GPGEngineInfoAsXMLString()) as soon as possible, because it also initializes
 * some subsystems. In a multithreaded environment if should be called
 * before the first thread is created. Note that it starts a dummy
 * NSThread to insure that Cocoa is ready for multithreading.
"*/
GPG_EXPORT NSString	*GPGCheckVersion(NSString *requiredVersion);

/*"
 * Checks whether the installed crypto engine matches the requirement of
 * GPGME.
 *
 * It is a pretty good idea to run this function (or #GPGCheckVersion() or
 * #GPGEngineInfoAsXMLString()) as soon as possible, because it also initializes
 * some subsystems. In a multithreaded environment if should be called
 * before the first thread is created. Note that it starts a dummy
 * NSThread to insure that Cocoa is ready for multithreading.
"*/
GPG_EXPORT GPGError	GPGCheckEngine();

/*"
 * Returns information about the underlying crypto engine. This is an
 * XML string with various information. To get the version of the
 * crypto engine it should be sufficient to grep for the first
 * version tag and use it's content. A string is
 * always returned even if the crypto engine is not installed; in this
 * case a XML string with some error information is returned.
 *
 * !{<GnupgInfo>
 *  <engine>"
 *   <version>aString</version>
 *   <path>aString</path>
 *  </engine>
 * </GnupgInfo>}
 *
 *  or
 *
 * !{<GnupgInfo>"
 *  <engine>"
 *   <error>aString</error>
 *   <path>aString</path> (optional)
 *  </engine>
 * </GnupgInfo>}
 *
 * It is a pretty good idea to run this function (or #GPGCheckVersion() or
 * #GPGCheckEngine()) as soon as possible, because it also initializes
 * some subsystems. In a multithreaded environment if should be called
 * before the first thread is created. Note that it starts a dummy
 * NSThread to insure that Cocoa is ready for multithreading.
"*/
GPG_EXPORT NSString	*GPGEngineInfoAsXMLString();

/*"
 * Messages are not yet localized, but they will be.
"*/
GPG_EXPORT NSString	*GPGErrorDescription(GPGError error);
