//
//  GPGContext.h
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

#import <GPGME/GPGObject.h>
#import <GPGME/GPGEngine.h>
#import <GPGME/GPGSignature.h>


@class NSArray;
@class NSCalendarDate;
@class NSEnumerator;
@class NSMutableDictionary;
@class GPGData;
@class GPGKey;
@class GPGRecipients;


/*"
 * The #GPGSignatureMode type is used to specify the desired type of a signature.
 * The following modes are available:
 * _{GPGSignatureModeNormal  A normal signature is made, the output includes the plaintext and the signature.}
 * _{GPGSignatureModeDetach  A detached signature is made.}
 * _{GPGSignatureModeClear   A clear text signature is made.
 *                           The %{ASCII armor} and %{text mode} settings of the context are ignored.}
"*/
typedef enum {
    GPGSignatureModeNormal = 0,
    GPGSignatureModeDetach = 1,
    GPGSignatureModeClear  = 2
} GPGSignatureMode;


/*"
 * The key listing mode is a combination of one or multiple of the following bit values:
 * _{GPGKeyListModeLocal       Specifies that the local %{key ring} should be searched
 *                             for keys in the key listing operation.
 *                             This is the default.}
 * _{GPGKeyListModeExtern      Specifies that an external source should be searched for
 *                             keys in the key listing operation. The type of external
 *                             source is dependant on the crypto engine used.
 *                             For example, it can be a remote %{key server} or LDAP
 *                             certificate server.}
 * _{GPGKeyListModeSignatures  .}
"*/
typedef enum {
    GPGKeyListModeLocal      = 1 << 0,
    GPGKeyListModeExtern     = 1 << 1,
    GPGKeyListModeSignatures = 1 << 2
}GPGKeyListMode;


/*"
 * Certificates inclusion (S/MIME only):
 * _{GPGAllExceptRootCertificatesInclusion  Include all certificates except the root certificate.}
 * _{GPGAllCertificatesInclusion            Include all certificates.}
 * _{GPGNoCertificatesInclusion             Include no certificates.}
 * _{GPGOnlySenderCertificateInclusion      Include the sender's certificate only.}
 * _{n                                      Include the first n certificates of the certificates path,
 *                                          starting from the sender's certificate.
 *                                          The number n must be positive.}
"*/
typedef enum {
    GPGAllExceptRootCertificatesInclusion = -2,
    GPGAllCertificatesInclusion           = -1,
    GPGNoCertificatesInclusion            = -0,
    GPGOnlySenderCertificateInclusion     =  1
}GPGCertificatesInclusion;


/*"
 * Posted whenever GPGME thinks that it is idle and time can be better
 * spent elsewhere.
 * 
 * Object is nil; no userInfo.
"*/
GPG_EXPORT NSString	* const GPGIdleNotification;


/*"
 * Posted after a modification to a keyring has been done. For example,
 * after an import or delete operation.
 *
 * Object is (currently) nil.
 *
 * UserInfo:
 * _{GPGContextKey The #GPGContext instance in which the operation was executed.}
 * 
"*/
GPG_EXPORT NSString	* const GPGKeyringChangedNotification;
GPG_EXPORT NSString	* const GPGContextKey;


/*"
 * Posted when progress information about a cryptographic operation is available,
 * for example during key generation.
 *
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 *
 * Currently it is used only during key generation.
 *
 * UserInfo:
 * _{description  String...}
 * _{type         String containing the letter printed during key generation.}
 * _{current      Amount done, as #NSNumber.}
 * _{total        Amount to be done, as #NSNumber. 0 means that the total amount is not known.}
 * current/total = 100/100 may be used to detect the end of operation.
"*/
GPG_EXPORT NSString	* const GPGProgressNotification;


@interface GPGContext : GPGObject /*"NSObject"*/
{
    id	_passphraseDelegate; /*"Passphrase delegate, not retained."*/
}

/*"
 * Initializer
"*/
- (id) init;

/*"
 * Notations
"*/
- (NSString *) notationsAsXMLString;

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
 * Operation status
"*/
- (NSString *) statusAsXMLString;

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

/*"
 * Including certificates (S/MIME only)
"*/
- (void) setCertificatesInclusion:(int)includedCertificatesNumber;
- (int) certificatesInclusion;

@end


@interface GPGContext(GPGAsynchronousOperations)
/*"
 * Asynchronous operations (#{NOTE THAT ASYNCHRONOUS OPERATIONS DON'T WORK RIGHT NOW.})
"*/
- (void) cancelOperation;
+ (GPGContext *) waitOnAnyRequest:(BOOL)hang;
- (BOOL) wait:(BOOL)hang;
@end


@interface GPGContext(GPGSynchronousOperations)
/*"
 * Crypto operations
"*/
/*"
 * Decrypt
"*/
- (GPGData *) decryptedData:(GPGData *)inputData;
/*"
 * Verify
"*/
- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData;
- (GPGSignatureStatus) verifySignedData:(GPGData *)signedData;
- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerprint:(NSString **)fingerprint;
- (GPGKey *) keyOfSignatureAtIndex:(int)index;
- (NSArray *) signatures;
/*"
 * Decrypt and verify
"*/
- (GPGData *) decryptedData:(GPGData *)inputData signatureStatus:(GPGSignatureStatus *)statusPtr;
/*"
 * Sign
"*/
- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode;
/*"
 * Encrypt
"*/
- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients allRecipientsAreValid:(BOOL *)allRecipientsAreValidPtr;
/*"
 * Encrypt and Sign
"*/
- (GPGData *) encryptedSignedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients allRecipientsAreValid:(BOOL *)allRecipientsAreValidPtr;
/*"
 * Symmetric Encryption (no key needed)
"*/
- (GPGData *) encryptedData:(GPGData *)inputData;
/*"
 * Managing keyring
"*/
- (GPGData *) exportedKeysForRecipients:(GPGRecipients *)recipients;
- (void) importKeyData:(GPGData *)keyData;
//- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr;
- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret;
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


@interface NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForKey:(GPGKey *)key again:(BOOL)again;
@end
