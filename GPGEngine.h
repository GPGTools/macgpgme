//
//  GPGEngine.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2002 Mac GPG Project.
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


/*"
 * The #GPGError type specifies the set of all error values that are used by GPGME.
 * Possible values are:
 * _{GPGErrorEOF               This value indicates the end of a list, buffer or file. Not used in GPGME framework.}
 * _{GPGErrorNoError           This value indicates success. No #GPGException is raised with this value.}
 * _{GPGErrorGeneralError      This value means that something went wrong,
 *                             but either there is not enough information 
 *                             about the problem to return a more useful error value, 
 *                             or there is no seperate error value for this type of problem.}
 * _{GPGErrorOutOfCore         This value means that an out-of-memory condition occured.}
 * _{GPGErrorInvalidValue      This value means that some user provided data was out of range. 
 *                             This can also refer to objects. For example, if an empty #GPGData 
 *                             instance was expected, but one containing data was provided, 
 *                             this error value is returned.}
 * _{GPGErrorBusy              This value is returned if you try to start a new operation
 *                             in a context that is already busy with some earlier operation 
 *                             which was not canceled or finished yet.}
 * _{GPGErrorNoRequest         This value is in some sense the opposite of #GPGErrorBusy. 
 *                             There is no pending operation, but it is required for the function to succeed.}
 * _{GPGErrorExecError         This value means that an error occured when trying to spawn a child process.}
 * _{GPGErrorTooManyProcs      This value means that there are too many active backend processes.}
 * _{GPGErrorPipeError         This value means that the creation of a pipe failed.}
 * _{GPGErrorNoRecipients      This value means that no %recipients for a message have been set.}
 * _{GPGErrorNoData            This value means that a #GPGData instance which was expected 
 *                             to have content was found empty.}
 * _{GPGErrorConflict          This value means that a conflict of some sort occured.}
 * _{GPGErrorNotImplemented    This value indicates that the specific operation is not implemented.
 *                             This error should never happen. It can only occur if you use certain 
 *                             values or configuration options which do not work, but for which we 
 *                             think that they should work at some later time.}
 * _{GPGErrorReadError         This value means that an I/O read operation failed.}
 * _{GPGErrorWriteError        This value means that an I/O write operation failed.}
 * _{GPGErrorInvalidType       This value means that a user provided object was of a wrong 
 *                             or incompatible type. Usually this refers to the type of a #GPGData instance.}
 * _{GPGErrorInvalidMode       This value means that a #GPGData instance has an 
 *                             incorrect mode of operation (for example, doesn't support 
 *                             output although it is attempted to use it as an output buffer).}
 * _{GPGErrorFileError         This value means that a file I/O operation failed. 
 *                             The value of #errno contains the system error value.}
 * _{GPGErrorDecryptionFailed  This value indicates that a decryption operation was unsuccessful.}
 * _{GPGErrorNoPassphrase      This value means that the user did not provide a passphrase when requested.}
 * _{GPGErrorCanceled          This value means that the operation was canceled.}
 * _{GPGErrorInvalidKey        This value means that a key was invalid.}
 * _{GPGErrorInvalidEngine     This value means that the engine that implements the
 *                             desired protocol is currently not available. This can 
 *                             either be because the sources were configured to exclude 
 *                             support for this engine, or because the engine is not installed properly.}
"*/
typedef enum {
    GPGErrorEOF              = -1,
    GPGErrorNoError          =  0,
    GPGErrorGeneralError     =  1,
    GPGErrorOutOfCore        =  2,
    GPGErrorInvalidValue     =  3,
    GPGErrorBusy             =  4,
    GPGErrorNoRequest        =  5,
    GPGErrorExecError        =  6,
    GPGErrorTooManyProcs     =  7,
    GPGErrorPipeError        =  8,
    GPGErrorNoRecipients     =  9,
    GPGErrorNoData           = 10,
    GPGErrorConflict         = 11,
    GPGErrorNotImplemented   = 12,
    GPGErrorReadError        = 13,
    GPGErrorWriteError       = 14,
    GPGErrorInvalidType      = 15,
    GPGErrorInvalidMode      = 16,
    GPGErrorFileError        = 17,
    GPGErrorDecryptionFailed = 18,
    GPGErrorNoPassphrase     = 19,
    GPGErrorCanceled         = 20,
    GPGErrorInvalidKey       = 21,
    GPGErrorInvalidEngine    = 22 
} GPGError;


/*"
 * The #GPGProtocol type specifies the set of possible protocol values that are supported by GPGME.
 * The following protocols are supported:
 * _{GPGOpenPGPProtocol  Default protocol. OpenPGP is implemented by GnuPG, the GNU Privacy Guard.
                         This is the first protocol that was supported by GPGME.}
 * _{GPGCMSProtocol      CMS is implemented by GpgSM, the S/MIME implementation for GnuPG.
 *                       #CAUTION: currently unsupported on MacOS X.}
"*/
typedef enum {
    GPGOpenPGPProtocol   = 0,
    GPGCMSProtocol       = 1,
    GPGAutomaticProtocol = 2
} GPGProtocol;


/*"
 * Checks that the version of the framework is at minimum the requested one
 * and returns the version string; returns nil if the condition is not
 * met or requiredVersion is not a valid version number.
 * If requiredVersion is nil, no check is done and
 * the version string is simply returned.
 *
 * Note that this check is automatically performed before any GPGME object/function
 * is used; it is called from #+[GPGObject initialize].
"*/
GPG_EXPORT NSString	*GPGCheckVersion(NSString *requiredVersion);

/*"
 * #{OBSOLETE. Use GPGEngineCheckVersion().}
 *
 * Check whether the installed crypto engine for the OpenPGP protocol
 * matches the requirement of GPGME.  This function is deprecated,
 * instead use #{GPGEngineCheckVersion()} with the specific protocol you
 * need.
"*/
GPG_EXPORT GPGError	GPGCheckEngine();

/*"
 * Checks that the engine implementing the protocol protocol is installed
 * in the expected path and meets the version requirement of GPGME.
 *
 * This function returns #GPGErrorNoError if the engine is available
 * and #GPGErrorInvalidEngine if it is not.
"*/
GPG_EXPORT GPGError GPGEngineCheckVersion(GPGProtocol protocol);

/*"
 * Returns information about the underlying crypto engines. This is an
 * XML string with various information. To get the version of the
 * crypto engine it should be sufficient to grep for the first
 * version tag and use it's content. A string is
 * always returned even if the crypto engine is not installed; in this
 * case an XML string with some error information is returned.
 *
 * !{<EngineInfo>
 *  <engine>
 *   <protocol>aString</protocol> (the name of the protocol, OpenPGP or CMS)
 *   <version>aString</version> (the version of the engine)
 *   <path>aString</path> (the path to the engine binary)
 *  </engine>
 *  <engine> (optional, for additional engines)
 *   <protocol>aString</protocol> (OpenPGP or CMS)
 *   <version>aString</version>
 *   <path>aString</path>
 *  </engine>
 * </EngineInfo>}
 *
 *  or
 *
 * !{<EngineInfo>
 *  <engine>
 *   <error>aString</error> (description of the failure)
 *   <path>aString</path> (optional)
 *  </engine>
 * </EngineInfo>}
"*/
GPG_EXPORT NSString	*GPGEngineInfoAsXMLString();

/*"
 * Returns the (yet unlocalized) description of the error value.
 * This string can be used to output a diagnostic message to the user.
"*/
GPG_EXPORT NSString	*GPGErrorDescription(GPGError error);
