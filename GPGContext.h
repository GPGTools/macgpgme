//
//  GPGContext.h
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2005 Mac GPG Project.
//  
//  This code is free software; you can redistribute it and/or modify it under
//  the terms of the GNU Lesser General Public License as published by the Free
//  Software Foundation; either version 2.1 of the License, or (at your option)
//  any later version.
//  
//  This code is distributed in the hope that it will be useful, but WITHOUT ANY
//  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
//  FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
//  details.
//  
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program; if not, visit <http://www.gnu.org/> or write to the
//  Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, 
//  MA 02111-1307, USA.
//  
//  More info at <http://macgpg.sourceforge.net/>
//

#ifndef GPGCONTEXT_H
#define GPGCONTEXT_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGEngine.h>
#include <MacGPGME/GPGSignatureNotation.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSArray;
@class NSCalendarDate;
@class NSEnumerator;
@class NSMutableDictionary;
@class NSMutableSet;
@class GPGData;
@class GPGKey;


/*"
 * The #GPGSignatureMode type is used to specify the desired type of a 
 * signature. The following modes are available:
 * _{GPGSignatureModeNormal  A normal signature is made, the output includes
 *                           the plaintext and the signature.}
 * _{GPGSignatureModeDetach  A detached signature is made.}
 * _{GPGSignatureModeClear   A clear text signature is made. The %ASCII %armor
 *                           and %{text mode} settings of the context are
 *                           ignored.}
"*/
typedef enum {
    GPGSignatureModeNormal = 0,
    GPGSignatureModeDetach = 1,
    GPGSignatureModeClear  = 2
} GPGSignatureMode;


/*"
 * The key listing mode is a combination of one or multiple of the following
 * bit values:
 * _{GPGKeyListModeLocal       Specifies that the local %{key-ring} should be 
 *                             searched for keys in the key listing operation.
 *                             This is the default.}
 * _{GPGKeyListModeExtern      Specifies that an external source should be 
 *                             searched for keys in the key listing operation.
 *                             The type of external source is dependant on the
 *                             crypto engine used. For example, it can be a 
 *                             remote %{key server} or LDAP certificate
 *                             server.}
 * _{GPGKeyListModeSignatures  Specifies that signatures on keys shall be
 *                             retrieved too. This is a time-consuming 
 *                             operation, and that mode should not be used
 *                             when retrieving all keys, but only a key per
 *                             key basis, like when using #{-refreshKey:}.}
 * _{GPGKeyListModeValidate    Specifies that the backend should do key or
 *                             certificate validation and not just get the
 *                             validity information from an internal cache.
 *                             This might be an expensive operation and is in
 *                             general not useful. Currently only implemented
 *                             for the S/MIME backend and ignored for other
 *                             backends.}
"*/
typedef unsigned int GPGKeyListMode;

#define GPGKeyListModeLocal         1
#define GPGKeyListModeExtern        2
#define GPGKeyListModeSignatures    4
#define GPGKeyListModeValidate    256


/*"
 * Certificates inclusion (S/MIME only):
 * _{GPGDefaultCertificatesInclusion        Use whatever the default of the 
 *                                          backend crypto engine is.}
 * _{GPGAllExceptRootCertificatesInclusion  Include all certificates except
 *                                          the root certificate.}
 * _{GPGAllCertificatesInclusion            Include all certificates.}
 * _{GPGNoCertificatesInclusion             Include no certificates.}
 * _{GPGOnlySenderCertificateInclusion      Include the sender's certificate
 *                                          only.}
 * _{n                                      Include the first n certificates
 *                                          of the certificates path, starting
 *                                          from the sender's certificate. The
 *                                          number n must be positive.}
"*/
typedef enum {
    GPGDefaultCertificatesInclusion       = -256,
    GPGAllExceptRootCertificatesInclusion =   -2,
    GPGAllCertificatesInclusion           =   -1,
    GPGNoCertificatesInclusion            =   -0,
    GPGOnlySenderCertificateInclusion     =    1
}GPGCertificatesInclusion;


/*"
 * The 'status' value of a key import is a combination of the following bit
 * values:
 * _{GPGImportDeletedKeyMask  Key has been removed from the key-ring}
 * _{GPGImportNewKeyMask      Key is new in the key-ring}
 * _{GPGImportNewUserIDMask   Some new userIDs has been imported, or updated}
 * _{GPGImportSignatureMask   Some new key signatures have been imported, or
 *                            updated}
 * _{GPGImportSubkeyMask      Some new subkeys have been imported, or updated}
 * _{GPGImportSecretKeyMask   Key is a secret key, and is new in the secret
 *                            key-ring}
"*/
typedef unsigned int GPGImportStatus;

#define GPGImportDeletedKeyMask  0
#define GPGImportNewKeyMask      1
#define GPGImportNewUserIDMask   2
#define GPGImportSignatureMask   4
#define GPGImportSubkeyMask      8
#define GPGImportSecretKeyMask  16


/*"
 * Posted after a modification to a key-ring has been done. For example,
 * after an import or delete operation.
 *
 * Object is (currently) nil.
 *
 * This notification is also posted by the distributed notification center.
 * object is also nil.
 *
 * UserInfo:
 * _{GPGContextKey  The #GPGContext instance in which the operation was
 *                  executed. Not available in distributed notifications.}
 * _{GPGChangesKey  An #NSDictionary whose keys are GPGKey instances
 *                  (secret and public keys) and whose values are NSDictionary 
 *                  instances containing key-value pair @"status" with a
 *                  GPGImportStatus (as NSNumber), and possibly @"error"
 *                  with a GPGError (as NSNumber). For distributed 
 *                  notifications, GPGKey instances are replaced by NSString
 *                  instances representing the key fingerprints.}
"*/
GPG_EXPORT NSString	* const GPGKeyringChangedNotification;
GPG_EXPORT NSString	* const GPGContextKey;
GPG_EXPORT NSString	* const GPGChangesKey;


/*"
 * Posted when progress information about a cryptographic operation is 
 * available, for example during key generation.
 *
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 *
 * Currently it is used only during key generation.
 *
 * Notification is always posted in the main thread.
 *
 * UserInfo:
 * _{@"description"  String...}
 * _{@"type"         String containing the letter printed during key
 *                   generation.}
 * _{@"current"      Amount done, as #NSNumber.}
 * _{@"total"        Amount to be done, as #NSNumber. 0 means that the total
 *                   amount is not known.}
 * current/total = 100/100 may be used to detect the end of operation.
"*/
GPG_EXPORT NSString	* const GPGProgressNotification;


/*"
 * Posted when an asynchronous operation on a context has been terminated,
 * for example during extended key search, or key upload. Object is the
 * context whose operation has just terminated, successfully or not.
 *
 * Notification is always posted in the main thread.
 *
 * UserInfo:
 * _{GPGErrorKey  A #NSNumber containing a #GPGError value}
"*/
GPG_EXPORT NSString	* const GPGAsynchronousOperationDidTerminateNotification;


GPG_EXPORT NSString	* const GPGNextKeyNotification;
GPG_EXPORT NSString	* const GPGNextKeyKey;


GPG_EXPORT NSString	* const GPGNextTrustItemNotification;
GPG_EXPORT NSString	* const GPGNextTrustItemKey;


@interface GPGContext : GPGObject <NSCopying> /*"NSObject"*/
{
    id					_passphraseDelegate; /*"Passphrase delegate, not retained."*/
    int					_operationMask;
    NSMutableDictionary	*_operationData;
    id					_userInfo; /*"Object set by user; not used by GPGContext itself."*/
    NSMutableSet		*_signerKeys;
    NSArray             *_engines;
}

/*"
 * Initializer
"*/
- (id) init;

/*"
 * ASCII armor
"*/
- (void) setUsesArmor:(BOOL)armor;
- (BOOL) usesArmor;

/*"
 * Text mode
"*/
- (void) setUsesTextMode:(BOOL)mode;
- (BOOL) usesTextMode;

/*"
 * Key listing mode
"*/
- (void) setKeyListMode:(GPGKeyListMode)mask;
- (GPGKeyListMode) keyListMode;

/*"
 * Protocol selection
"*/
- (void) setProtocol:(GPGProtocol)protocol;
- (GPGProtocol) protocol;

/*"
 * Passphrase delegate
"*/
- (void) setPassphraseDelegate:(id)delegate;
- (id) passphraseDelegate;

/*"
 * Selecting signers
"*/
- (void) clearSignerKeys;
- (void) addSignerKey:(GPGKey *)key;
- (NSEnumerator *) signerKeyEnumerator;
- (NSArray *) signerKeys;

/*"
 * Including certificates (S/MIME only)
"*/
- (void) setCertificatesInclusion:(int)includedCertificatesNumber;
- (int) certificatesInclusion;

/*"
 * Operation results
"*/
- (NSDictionary *) operationResults;

/*"
 * Contextual information
"*/
- (void) setUserInfo:(id)userInfo;
- (id) userInfo;

/*"
 * Signature notations    
"*/
- (void) clearSignatureNotations;
- (void) addSignatureNotationWithName:(NSString *)name value:(id)value flags:(GPGSignatureNotationFlags)flags;
- (NSArray *) signatureNotations;

/*"
 * Engines
"*/
- (NSArray *) engines;
- (GPGEngine *) engine;

@end


@interface GPGContext(GPGAsynchronousOperations)
/*"
 * Asynchronous operations (#{NOTE THAT ASYNCHRONOUS OPERATIONS DON'T WORK RIGHT NOW.})
"*/
+ (GPGContext *) waitOnAnyRequest:(BOOL)hang;
- (BOOL) wait:(BOOL)hang;
- (void) cancel;
@end


@interface GPGContext(GPGSynchronousOperations)
/*"
 * #{Crypto operations}
"*/
/*"
 * Decrypt
"*/
- (GPGData *) decryptedData:(GPGData *)inputData;
/*"
 * Verify
"*/
- (NSArray *) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData;
- (NSArray *) verifySignedData:(GPGData *)signedData;
- (NSArray *) verifySignedData:(GPGData *)signedData originalData:(GPGData **)originalDataPtr;
- (NSArray *) signatures;
/*"
 * Decrypt and verify
"*/
- (GPGData *) decryptedData:(GPGData *)inputData signatures:(NSArray **)signaturesPtr;
/*"
 * Sign
"*/
- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode;
/*"
 * Encrypt
"*/
- (GPGData *) encryptedData:(GPGData *)inputData withKeys:(NSArray *)recipientKeys trustAllKeys:(BOOL)trustAllKeys;
/*"
 * Encrypt and Sign
"*/
- (GPGData *) encryptedSignedData:(GPGData *)inputData withKeys:(NSArray *)keys trustAllKeys:(BOOL)trustAllKeys;
/*"
 * Symmetric Encryption (no key needed)
"*/
- (GPGData *) encryptedData:(GPGData *)inputData;
/*"
 * Managing key-ring
"*/
- (GPGData *) exportedKeys:(NSArray *)recipientKeys;
- (NSDictionary *) importKeyData:(GPGData *)keyData;
- (NSDictionary *) generateKeyFromDictionary:(NSDictionary *)params secretKey:(GPGData *)secretKeyData publicKey:(GPGData *)publicKeyData;
- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret;
/*"
 * Finding/refreshing a single key
"*/
- (GPGKey *) keyFromFingerprint:(NSString *)fingerprint secretKey:(BOOL)secretKey;
- (GPGKey *) refreshKey:(GPGKey *)key;

@end


@interface GPGContext(GPGKeyManagement)
/*"
 * Listing keys
"*/
- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly;
- (NSEnumerator *) keyEnumeratorForSearchPatterns:(NSArray *)searchPatterns secretKeysOnly:(BOOL)secretKeysOnly;
- (void) stopKeyEnumeration;
/*"
 * Listing trust items
"*/
- (NSEnumerator *) trustItemEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel;
- (void) stopTrustItemEnumeration;
@end


@interface GPGContext(GPGExtendedKeyManagement)
/*"
 * Searching keys on a key server
"*/
- (void) asyncSearchForKeysMatchingPatterns:(NSArray *)searchPatterns serverOptions:(NSDictionary *)options;
- (void) asyncDownloadKeys:(NSArray *)keys serverOptions:(NSDictionary *)options;
/*"
 * Uploading keys on a key server
"*/
- (void) asyncUploadKeys:(NSArray *)keys serverOptions:(NSDictionary *)options;

/*"
 * Interrupting async operations
"*/
- (void) interruptAsyncOperation;


/*"
 * context is busy with an async operation
"*/
-(BOOL) isPerformingAsyncOperation;

@end


@interface GPGContext(GPGKeyGroups)
/*"
 * Getting key groups
"*/
- (NSArray *) keyGroups;
@end


@interface NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForKey:(GPGKey *)key again:(BOOL)again;
@end


#ifdef __cplusplus
}
#endif
#endif /* GPGCONTEXT_H */
