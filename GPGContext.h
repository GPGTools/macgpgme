//
//  GPGContext.h
//  GPGME
//
//  Created by stephane@sente.ch on Tue Aug 14 2001.
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
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx> or
//  <stephane@sente.ch>.
//

#import <GPGME/GPGObject.h>
#import <GPGME/GPGEngine.h>


@class NSCalendarDate;
@class NSMutableDictionary;
@class GPGData;
@class GPGKey;
@class GPGRecipients;


typedef enum {
    GPGSignatureStatusNone        = 0,	// No status - should not happen
    GPGSignatureStatusGood        = 1,	// The signature is valid
    GPGSignatureStatusBad         = 2,	// The signature is not valid
    GPGSignatureStatusNoKey       = 3,	// The signature could not be checked due to a missing key
    GPGSignatureStatusNoSignature = 4,	// This is not a signature
    GPGSignatureStatusError       = 5,	// Due to some other error the check could not be done
    GPGSignatureStatusDifferent   = 6	// There is more than 1 signature and they have not the same status
} GPGSignatureStatus;


typedef enum {
    GPGSignatureModeNormal = 0,
    GPGSignatureModeDetach = 1,
    GPGSignatureModeClear  = 2
} GPGSignatureMode;


GPG_EXPORT NSString	* const GPGIdleNotification;
// Object is nil; no userInfo
// Posted when a call to +[GPGContext waitOnAnyRequest:] or -[GPGContext wait:]
// is done with argument YES and there is a pending request


@interface GPGContext : GPGObject
{
    id	_passphraseDelegate;
    id	_progressDelegate;
}

- (id) init;
// Designated initializer
// Can raise a GPGException; in this case, a release is sent to self

// Methods to use for asynchronous operations:
- (void) cancel;
/*
 * Cancel the current operation. It is not guaranteed that it will work for
 * all kinds of operations. It is especially useful in a passphrase callback
 * to stop the system from asking another time for the passphrase.
 */
+ (GPGContext *) waitOnAnyRequest:(BOOL)hang;
/*
 * Wait for any finished request. When hang is YES the method will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * If hang is YES, GPGIdleNotification can be posted.
 *
 * Return the context of the finished request or nil if hang is NO
 * and no request has finished.
 */
- (BOOL) wait:(BOOL)hang;
/*
 * Wait for a finsihed request for context.
 * When hang is YES the method will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * If hang is YES, GPGIdleNotification can be posted.
 *
 * Return YES if there is a finished request for context or NO if hang is NO
 * and no request (for context) has finished.
 */

- (NSString *) xmlNotation;
/*
 * If there is notation data available from the last signature check, this
 * method may be used to return this notation data as a string. The string
 * is an XML representation of that data embedded in a <notation> container.
 * <notation>
 *   <name>aString</name>
 *   <data>aString</data>
 *   <policy>aString</policy>
 * </notation>
 *
 * Return value: An XML string or nil if no notation data is available.
 */
- (void) setArmor:(BOOL)armor;
// Enable or disable the use of an ascii armor for all output.
// Default value is NO.
- (void) setTextMode:(BOOL)mode;
// Enable or disable the use of the special textmode.  Textmode is for example
// used for MIME (RFC2015) signatures
// Default value is NO.
- (void) setFastKeyListMode:(BOOL)mode;
/*
 * This method changes the default behaviour of the keylisting methods.
 * Fast listing doesn't give information about key validity.
 * Default value is NO.
 */

- (void) setPassphraseDelegate:(id)delegate;
/*
 * This methods allows a delegate to be used to pass a passphrase
 * to gpg. The preferred way to handle this is by using the gpg-agent, but
 * because that beast is not ready for real use, you can use this passphrase
 * thing.
 * Delegate is not retained.
 */
- (void) setProgressDelegate:(id)delegate;
/*
 * This method allows a delegate to update a progress indicator.
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 * Delegate is not retained.
 */

- (void) clearSigners;
- (void) addSigner:(GPGKey *)key;
// BUG: valid only for signing operation, not for encryption
//      => impossible to encrypt+sign
// Does NOT retain key!
// Can raise a GPGException
- (NSEnumerator *) signerEnumerator;
// Enumerated objects are GPGKey instances

- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerPrint:(NSString **)fingerPrint;
// Returns GPGSignatureStatusNone if there are no results yet, or there was
// a verification error, or there is no signature at index index
// index starts at 0
- (GPGKey *) keyOfSignatureAtIndex:(int)index;
// Return the key which was used to check the signature
// index starts at 0
// Returns nil if there is no signature at index index
// Can raise a GPGException (except a GPGErrorEOF)

@end


@interface GPGContext(GPGBasic)
@end


@interface GPGContext(GPGNormalUsage)
// All these methods can raise a GPGException
- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData;
// Use this method for detached signatures
// If result is GPGSignatureStatusDifferent or there are more than one signature,
// use -statusOfSignatureAtIndex:creationDate:fingerPrint: to get all signatures status
- (GPGSignatureStatus) verifySignedData:(GPGData *)signedData;
// If result is GPGSignatureStatusDifferent or there are more than one signature,
// use -statusOfSignatureAtIndex:creationDate:fingerPrint: to get all signatures status
- (void) importKeyData:(GPGData *)keyData;
// Keys are imported into standard pubring file
//- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr;
/*
 * <GnupgKeyParms format="internal">
 *   Key-Type: DSA
 *   Key-Length: 1024
 *   Subkey-Type: ELG-E
 *   Subkey-Length: 1024
 *   Name-Real: Joe Tester
 *   Name-Comment: (pp=abc,try=%d)
 *   Name-Email: joe@foo.bar
 *   Expire-Date: 0
 *   Passphrase: abc
 * </GnupgKeyParms>
 * Strings should be given in UTF-8 encoding. The format we support for now
 * "internal". The content of the <GnupgKeyParms> container is passed
 * verbatim to GnuPG. Control statements (e.g. pubring) are not allowed.
 * Key is generated in standard secring/pubring files if both secretKeyPtr
 * and publicKeyPtr are NULL, else newly created key is returned but not stored
 * Currently cannot return generated secret/public keys
 */
- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret;
// BUG: it seems it doesn't work yet...
@end


@interface GPGContext(GPGExtended)
// All these methods can raise a GPGException
// These are synchronous forms of the methods defined in GPGBasic category
- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients;
// BUG: does not raise any exception if no recipient is trusted! (but it encrypts nothing)
- (GPGData *) decryptedData:(GPGData *)inputData;
// BUG: does not raise any exception if no valid passphrase is given
- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode;
// Data will be signed using either the default key or the ones defined
// in context. Note that settings done by -setArmor: and -setTextMode: are
// ignored for mode GPGSignatureModeClear.
- (GPGData *) exportedKeysForRecipients:(GPGRecipients *)recipients;
// Returns recipients public keys, wrapped in a GPGData instance
// Keys are exported from standard pubring file
@end


/*
 UserID search patterns:
 As a search pattern, you can give:
 - a key ID, in short or long form, prefixed or not by "0x"
 - a key fingerprint
 - using "=aString", where aString must be an exact match like "=Heinrich Heine <heinrichh@uni-duesseldorf.de>"
 - using the email address part, matching exactly: "<heinrichh@uni-duesseldorf.de>"
 - using a format like this: "+Heinrich Heine duesseldorf"
   All  words  must  match exactly (not case sensitive) but
   can appear in any order in the user ID.  Words are any
   sequences of letters, digits, the underscore and all
   characters with bit 7 set
 - or a substring matching format like that: "Heine" or "*Heine"
   By case insensitive substring matching. This is the default
   mode but applications may want to explicitely indicate this
   by putting the asterisk in front
 */

@interface GPGContext(GPGKeyManagement)
- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly;
// Enumerated objects are GPGKey instances
// searchPattern is a GnuPG user ID
// searchPattern can be nil; in this case all keys are returned
// If secretKeysOnly is YES, searches only for keys whose secret part is available
// This call also resets any pending key listing operation
// Can raise a GPGException, even during enumeration
- (NSEnumerator *) trustListEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel;
// Enumerated objects are GPGTrustItem instances
// searchPattern is a GnuPG user ID
// searchPattern cannot be nil nor empty
// Can raise a GPGException, even during enumeration
@end


@interface NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForDescription:(NSString *)description userInfo:(NSMutableDictionary *)userInfo;
// Description can be used as a prompt text (BUG: not yet localized)
// userInfo can be used to store contextual information
// It is passed from one call to another with the values you
// put into. By default it is empty.
- (void) context:(GPGContext *)context progressingWithDescription:(NSString *)what type:(int)type current:(int)current total:(int)total;
/*
 "current" is the current amount done and "total" is amount to be done;
 a "total" of 0 indicates that the total amount is not known.
 100/100 may be used to detect the end of operation
 */
@end
