//
//  GPGContext.h
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

#import <GPGME/GPGObject.h>
#import <GPGME/GPGEngine.h>


@class NSCalendarDate;
@class NSEnumerator;
@class NSMutableDictionary;
@class GPGData;
@class GPGKey;
@class GPGRecipients;


typedef enum {
    GPGSignatureStatusNone        = 0,	/*"No status - should not happen"*/
    GPGSignatureStatusGood        = 1,	/*"The signature is valid"*/
    GPGSignatureStatusBad         = 2,	/*"The signature is not valid"*/
    GPGSignatureStatusNoKey       = 3,	/*"The signature could not be checked due to a missing key"*/
    GPGSignatureStatusNoSignature = 4,	/*"This is not a signature"*/
    GPGSignatureStatusError       = 5,	/*"Due to some other error the check could not be done"*/
    GPGSignatureStatusDifferent   = 6	/*"There is more than 1 signature and they have not the same status"*/
} GPGSignatureStatus;


typedef enum {
    GPGSignatureModeNormal = 0,
    GPGSignatureModeDetach = 1,
    GPGSignatureModeClear  = 2
} GPGSignatureMode;


/*"
 * Posted when a call to #{+waitOnAnyRequest:} or #{wait:} is done with argument
 * YES and there is a pending request.
 * 
 * Object is nil; no userInfo
"*/
GPG_EXPORT NSString	* const GPGIdleNotification;


@interface GPGContext : GPGObject /*"NSObject"*/
{
    id	_passphraseDelegate;
    id	_progressDelegate;
}

/*"
 * Initializer
"*/
- (id) init;

/*"
 * Methods to use for asynchronous operations
"*/
- (void) cancel;
+ (GPGContext *) waitOnAnyRequest:(BOOL)hang;
- (BOOL) wait:(BOOL)hang;

/*"
 * Notations
"*/
- (NSString *) xmlNotation;

/*"
 * Attributes
"*/
- (void) setUsesArmor:(BOOL)armor;
- (BOOL) usesArmor;
- (void) setUsesTextMode:(BOOL)mode;
- (BOOL) usesTextMode;
- (void) setFastKeyListMode:(BOOL)fastMode;

/*"
 * Operation status
"*/
- (NSString *) xmlStatus;

/*"
 * Callbacks
"*/
- (void) setPassphraseDelegate:(id)delegate;
- (void) setProgressDelegate:(id)delegate;

/*"
 * Signers
"*/
- (void) clearSigners;
- (void) addSigner:(GPGKey *)key;
// BUG: valid only for signing operation, not for encryption
//      => impossible to encrypt+sign
// Does NOT retain key!
// Can raise a GPGException
- (NSEnumerator *) signerEnumerator;
// Enumerated objects are GPGKey instances

/*"
 * Authentication results
"*/
- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerprint:(NSString **)fingerprint;
- (GPGKey *) keyOfSignatureAtIndex:(int)index;

@end


@interface GPGContext(GPGBasic)
@end


@interface GPGContext(GPGNormalUsage)
/*"
 * Normal usage
"*/
// All these methods can raise a GPGException
- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData;
- (GPGSignatureStatus) verifySignedData:(GPGData *)signedData;
- (void) importKeyData:(GPGData *)keyData;
//- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr;
- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret;
// BUG: it seems it doesn't work yet...
@end


@interface GPGContext(GPGExtended)
// These are synchronous forms of the methods defined in GPGBasic category
/*"
 * Synchronous operations
"*/
- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients;
// BUG: does not raise any exception if no recipient is trusted! (but it encrypts nothing)
- (GPGData *) decryptedData:(GPGData *)inputData;
// BUG: does not raise any exception if no valid passphrase is given
- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode;
- (GPGData *) exportedKeysForRecipients:(GPGRecipients *)recipients;
@end


@interface GPGContext(GPGKeyManagement)
- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly;
- (NSEnumerator *) trustListEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel;
@end


@interface NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForDescription:(NSString *)description userInfo:(NSMutableDictionary *)userInfo;
- (void) context:(GPGContext *)context progressingWithDescription:(NSString *)what type:(int)type current:(int)current total:(int)total;
@end
