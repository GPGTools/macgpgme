//
//  GPGContext.m
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

#import "GPGContext.h"
#import "GPGData.h"
#import "GPGExceptions.h"
#import "GPGInternals.h"
#import "GPGKey.h"
#import "GPGRecipients.h"
#import "GPGTrustItem.h"
#import <Foundation/Foundation.h>
#import <time.h> /* Needed for GNUstep */
#import <gpgme.h>


#define _context	((GpgmeCtx)_internalRepresentation)


NSString	* const GPGIdleNotification = @"GPGIdleNotification";


@interface GPGSignerEnumerator : NSEnumerator
{
    GPGContext	*context;
    int			index;
}

- (id) initForContext:(GPGContext *)context;
// Designated initializer
// Can raise a GPGException; in this case, a release is sent to self

@end


@interface GPGKeyEnumerator : NSEnumerator
{
    GPGContext	*context;
}

- (id) initForContext:(GPGContext *)context searchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly;
// Designated initializer
// Can raise a GPGException; in this case, a release is sent to self

@end


@interface GPGTrustItemEnumerator : NSEnumerator
{
    GPGContext	*context;
}

- (id) initForContext:(GPGContext *)context searchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel;
// Designated initializer
// Can raise a GPGException; in this case, a release is sent to self

@end


@implementation GPGContext
/*"
 * UserID search patterns:
 * 
 * For search pattern, you can give:
 * 
 * - a key ID, in short or long form, prefixed or not by !{0x}
 * 
 * - a key fingerprint
 * 
 * - using "=aString", where aString must be an exact match like
 *   "=Heinrich Heine <heinrichh@uni-duesseldorf.de>"
 * 
 * - using the email address part, matching exactly:
 *   "<heinrichh@uni-duesseldorf.de>"
 * 
 * - using a format like this: "+Heinrich Heine duesseldorf". All words must
 *   match exactly (not case sensitive) but can appear in any order in the user
 *   ID. Words are any sequences of letters, digits, the underscore and all
 *   characters with bit 7 set.
 * 
 * - or a substring matching format like that: "Heine" or "*Heine". By case
 *   insensitive substring matching. This is the default mode but applications may
 *   want to explicitely indicate this by putting the asterisk in front.
"*/

static void idleFunction()
{
    // Let's hope that this function is not called repeatedly...
    // WARNING: it IS called very often!
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGIdleNotification object:nil];
}

+ (void) initialize
{
    static BOOL	initialized = NO;
    
    [super initialize];
    if(!initialized){
        initialized = YES;
        gpgme_register_idle(idleFunction);
    }
}

- (id) init
/*"
 * Designated initializer.
 * Creates a new context to be used with most of the other GPGME.
 * 
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError = gpgme_new((GpgmeCtx *)&_internalRepresentation);

    if(anError != GPGME_No_Error){
        _internalRepresentation = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_internalRepresentation];

    return self;
}

- (void) dealloc
{
    GpgmeCtx	cachedContext = _context;

    if(_context != NULL){
        gpgme_set_passphrase_cb(_context, NULL, NULL);
        gpgme_set_progress_cb(_context, NULL, NULL);
    }

    [super dealloc];

    if(cachedContext != NULL)
        gpgme_release(cachedContext);
}

- (void) cancel
/*"
 * Cancels the current operation. It is not guaranteed that it will work for
 * all kinds of operations. It is especially useful in a passphrase callback
 * to stop the system from asking another time for the passphrase.
"*/
{
    gpgme_cancel(_context);
}

+ (GPGContext *) waitOnAnyRequest:(BOOL)hang
/*"
 * Waits for any finished request. When hang is YES the method will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * If hang is YES, a #GPGIdleNotification may be posted.
 *
 * Returns the context of the finished request or nil if hang is NO
 * and no request has finished.
"*/
{
    GpgmeCtx	returnedCtx = gpgme_wait(NULL, hang);

    if(returnedCtx != NULL){
        // Returns an existing context
        GPGContext	*newContext = [[GPGContext alloc] initWithInternalRepresentation:returnedCtx];

        return [newContext autorelease];
    }
    else
        return nil;
}

- (BOOL) wait:(BOOL)hang;
/*"
 * Waits for a finished request for context.
 * When hang is YES the method will wait, otherwise
 * it will return immediately when there is no pending finished request.
 * If hang is YES, a #GPGIdleNotification may be posted.
 *
 * Returns YES if there is a finished request for context or NO if hang is NO
 * and no request (for context) has finished.
"*/
{
    GpgmeCtx	returnedCtx = gpgme_wait(_context, hang);

    if(returnedCtx == _context)
        return YES;
    else
        return (returnedCtx != NULL);
}

- (NSString *) xmlNotation
/*"
 * If there is notation data available from the last signature check, this
 * method may be used to return this notation data as a string. The string
 * is an XML representation of that data embedded in a !{<notation>} container.
 *
 * !{<notation>
 *   <name>aString</name>
 *   <data>aString</data>
 *   <policy>aString</policy>
 * </notation>}
 *
 * Returns an XML string or nil if no notation data is available.
"*/
{
#warning Use method returning a NSDictionary for XML content
    char		*aCString = gpgme_get_notation(_context);
    NSString	*aString = nil;

    if(aCString != NULL){
        aString = [NSString stringWithUTF8String:aCString];
        free(aCString);
    }

    return aString;
}

- (void) setUsesArmor:(BOOL)armor
/*"
 * Enables or disables the use of an %{ASCII armor} for all output.
 *
 * Default value is NO.
"*/
{
    gpgme_set_armor(_context, armor);
}

- (BOOL) usesArmor
/*"
 * Returns whether context uses ASCII armor or not. Default value is NO.
"*/
{
    return gpgme_get_armor(_context) != 0;
}

- (void) setUsesTextMode:(BOOL)mode
/*"
 * Enables or disables the use of the special %textmode. Textmode is for
 * example used for MIME (RFC2015) signatures.
 * 
 * Default value is NO.
"*/
{
    gpgme_set_textmode(_context, mode);
}

- (BOOL) usesTextMode
/*"
 * Returns whether context uses textmode or not. Default value is NO.
"*/
{
    return gpgme_get_textmode(_context) != 0;
}

- (void) setFastKeyListMode:(BOOL)fastMode
/*"
 * Changes the default behaviour of the key listing methods.
 * %{Fast listing} doesn't give information about key validity.
 *
 * Default value is NO.
"*/
{
    gpgme_set_keylist_mode(_context, !!fastMode);
}

- (NSString *) xmlStatus
/*"
 * Returns information about the last operation, as an XML string.
 * Returns nil if there is no previous
 * operation available or the operation has not yet finished.
 *
 * Here is a sample information we return:
 * !{<GnupgOperationInfo>
 *   <signature>
 *     <detached/> <!-- or cleartext or standard -->
 *     <algo>17</algo>
 *     <hashalgo>2</hashalgo>
 *     <micalg>pgp-sha1</micalg>
 *     <sigclass>01</sigclass>
 *     <created>9222222</created>
 *     <fpr>121212121212121212</fpr>
 *   </signature>
 * </GnupgOperationInfo>}
"*/
#warning See sign.c for more info on format
{
    char	*aCString = gpgme_get_op_info(_context, 0);

    if(aCString != NULL){
        NSString	*aString = [NSString stringWithUTF8String:aCString];

        free(aCString);

        return aString;
    }
    else
        return nil;
}

- (NSDictionary *) status
{
    char			*aCString = gpgme_get_op_info(_context, 0);
    NSDictionary	*aDictionary = nil;

    if(aCString != NULL){
        aDictionary = [[GPGXMLParser parsedDictionaryFromCString:aCString] objectForKey:@"GnupgOperationInfo"];
#warning Replace elements
        // signature -> signatures (array)
        // algo -> NSNumber
        // hashalgo -> NSNumber
        // created -> NSCalendarDate
        free(aCString);
    }

    return aDictionary;
}

static const char *passphraseCallback(void *object, const char *description, void *r_hd)
{
    NSString	*aDescription;
    NSString	*aPassphrase;

    NSCAssert(r_hd != NULL, @"### passphraseCallback's r_hd is NULL?!");
    if(description == NULL){
        // We can now release resources associated with returned value
        if(*((void **)r_hd) != NULL){
            [(*((NSMutableDictionary **)r_hd)) release];
            *((void **)r_hd) = NULL;
        }
        
        return NULL;
    }
    aDescription = [NSString stringWithUTF8String:description];

    if(*((void **)r_hd) == NULL)
        *((void **)r_hd) = [[NSMutableDictionary alloc] initWithObjectsAndKeys:[NSMutableDictionary dictionary], @"userInfo", nil];

    aPassphrase = [((GPGContext *)object)->_passphraseDelegate context:((GPGContext *)object) passphraseForDescription:aDescription userInfo:[(*((NSMutableDictionary **)r_hd)) objectForKey:@"userInfo"]];

    if(aPassphrase == nil)
        return NULL;
    else{
        // We cannot simply pass [aPassphrase UTF8String], because
        // the buffer is autoreleased!!!
        const char	*aCString = [aPassphrase UTF8String];
        NSData		*passphraseAsData = [NSData dataWithBytes:aCString length:strlen(aCString)];

        [(*((NSMutableDictionary **)r_hd)) setObject:passphraseAsData forKey:@"passphraseAsData"];
        return [passphraseAsData bytes];
    }
}

static void progressCallback(void *object, const char *description, int type, int current, int total)
{
    // The <type> parameter is the letter printed during key generation 
    NSString	*aDescription = nil;

    if(description != NULL)
        aDescription = [NSString stringWithUTF8String:description];
    [((GPGContext *)object)->_progressDelegate context:((GPGContext *)object) progressingWithDescription:aDescription type:type current:current total:total];
}

- (void) setPassphraseDelegate:(id)delegate
/*"
 * This methods allows a delegate to be used to pass a passphrase
 * to gpg. The preferred way to handle this is by using the gpg-agent, but
 * because that beast is not ready for real use, you can use this passphrase
 * thing.
 *
 * Delegate must respond to #context:passphraseForDescription:userInfo:.
 * Delegate is not retained.
"*/
{
    NSParameterAssert(delegate == nil || [delegate respondsToSelector:@selector(context:passphraseForDescription:userInfo:)]);
    _passphraseDelegate = delegate; // We don't retain delegate
    if(delegate == nil)
        gpgme_set_passphrase_cb(_context, NULL, NULL);
    else
        gpgme_set_passphrase_cb(_context, passphraseCallback, self);
}

- (void) setProgressDelegate:(id)delegate
/*"
 * This method allows a delegate to update a progress indicator.
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 *
 * Currently it is used only during key generation.
 *
 * Delegate must respond to #context:progressingWithDescription:type:current:total:.
 * Delegate is not retained.
"*/
{
    NSParameterAssert(delegate == nil || [delegate respondsToSelector:@selector(context:progressingWithDescription:type:current:total:)]);
    _progressDelegate = delegate; // We don't retain delegate
    if(delegate == nil)
        gpgme_set_progress_cb(_context, NULL, NULL);
    else
        gpgme_set_progress_cb(_context, progressCallback, self);
}

- (void) clearSigners
{
    gpgme_signers_clear(_context);
}

- (void) addSigner:(GPGKey *)key
/*"
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError;

    NSParameterAssert(key != nil);

#warning Should we retain key?
    anError = gpgme_signers_add(_context, [key gpgmeKey]);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSEnumerator *) signerEnumerator
/*"
 * Returns an enumerator of #GPGKey instances.
"*/
{
    return [[[GPGSignerEnumerator alloc] initForContext:self] autorelease];
}

- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerprint:(NSString **)fingerprintPtr
/*"
 * Returns #GPGSignatureStatusNone if there are no results yet, or there was a
 * verification error, or there is no signature at index index.
 * 
 * index starts at 0.
"*/
{
    GPGSignatureStatus	returnedStatus;
    time_t				aTime;
    const char			*aCString = gpgme_get_sig_status(_context, index, &returnedStatus, &aTime);

    if(fingerprintPtr != NULL){
        if(aCString != NULL)
            *fingerprintPtr = [NSString stringWithUTF8String:aCString];
        else
            *fingerprintPtr = nil;
    }

    if(creationDatePtr != NULL){
        // Are we sure that localtime() uses the same timeZone as [NSTimeZone localTimeZone]?
        struct tm	*aTimeStruct = localtime(&aTime);

        *creationDatePtr = [NSCalendarDate dateWithYear:(1900 + aTimeStruct->tm_year) month:(aTimeStruct->tm_mon + 1) day:aTimeStruct->tm_mday hour:aTimeStruct->tm_hour minute:aTimeStruct->tm_min second:aTimeStruct->tm_sec timeZone:[NSTimeZone localTimeZone]];
    }

    if(aCString == NULL)
        // No results yet or verification error or out-of-bounds
        returnedStatus = GPGSignatureStatusNone;
    
    return returnedStatus;
}

- (GPGKey *) keyOfSignatureAtIndex:(int)index
/*"
 * Returns the key which was used to check the signature.
 * 
 * index starts at 0.
 * 
 * Returns nil if there is no signature at index index.
 * 
 * Can raise a #GPGException (except a #GPGErrorEOF)
"*/
{
    GpgmeKey	aGpgmeKey;
    GpgmeError	anError = gpgme_get_sig_key(_context, index, &aGpgmeKey);

    if(anError == GPGME_EOF)
        return nil;

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aGpgmeKey != NULL, @"### No gpgmeKey but no error?!");
    
    return [[[GPGKey alloc] initWithInternalRepresentation:aGpgmeKey] autorelease];
}

@end


@implementation GPGContext(GPGBasic)
#warning Functions gpgme_op_start_XXX have no counterpart...
@end


@implementation GPGContext(GPGNormalUsage)

- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData
/*"
 * Use this method for %detached signatures.
 * 
 * If result is #GPGSignatureStatusDifferent or there are more than one
 * signature, use #{-statusOfSignatureAtIndex:creationDate:fingerprint:} to get
 * all signatures statuses.
 * 
 * Can raise a #GPGException.
"*/
{
    GPGSignatureStatus	returnedStatus;
    GpgmeError			anError = gpgme_op_verify(_context, [signatureData gpgmeData], [inputData gpgmeData], &returnedStatus);
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return returnedStatus;
}

- (GPGSignatureStatus) verifySignedData:(GPGData *)signedData
/*"
 * If result is #GPGSignatureStatusDifferent or there are more than one
 * signature, use #{-statusOfSignatureAtIndex:creationDate:fingerprint:} to get
 * all signatures statuses.
 * 
 * Can raise a #GPGException.
"*/
{
    GPGSignatureStatus	returnedStatus;
    GpgmeError			anError = gpgme_op_verify(_context, [signedData gpgmeData], NULL, &returnedStatus);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return returnedStatus;
}

- (void) importKeyData:(GPGData *)keyData
/*"
 * Imports all key material into the key database.
 * 
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_op_import(_context, [keyData gpgmeData]);
    // It would be nice if we could get imported keys in returned value...

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    // We could post a notification here...
}

#warning gpgme_op_genkey() has no counterpart
#if 0
- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr
/*"
 * Generates a new key and stores the key in the default keyrings if
 * both publicKeyPtr and secretKeyPtr are NULL. If publicKeyPtr and secretKeyPtr are
 * given, the newly created key will be returned in these data
 * objects.
 *
 * !{<GnupgKeyParms format="internal">
 *   Key-Type: DSA
 *   Key-Length: 1024
 *   Subkey-Type: ELG-E
 *   Subkey-Length: 1024
 *   Name-Real: Joe Tester
 *   Name-Comment: (pp=abc,try=%d)
 *   Name-Email: joe@foo.bar
 *   Expire-Date: 0
 *   Passphrase: abc
 * </GnupgKeyParms>}
 * Strings should be given in UTF-8 encoding. The format we support for now
 * "internal". The content of the !{<GnupgKeyParms>} container is passed
 * verbatim to GnuPG. Control statements (e.g. pubring) are not allowed.
 * Key is generated in standard secring/pubring files if both secretKeyPtr
 * and publicKeyPtr are NULL, else newly created key is returned but not stored
 * Currently cannot return generated secret/public keys.
 *
 * Can raise a #GPGException.
"*/
{
    // We could post a notification here...
}
#endif

- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret
/*"
 * Deletes the given key from the key database. To delete a secret key
 * along with the public key, allowSecret must be YES.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_op_delete(_context, [key gpgmeKey], allowSecret);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    // We could post a notification here...
}

@end


@implementation GPGContext(GPGKeyManagement)

- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly
/*"
 * Returns an enumerator of GPGKey instances.
 * 
 * searchPattern is a GnuPG %{user ID}. searchPattern can be nil; in this case
 * all keys are returned.
 * 
 * If secretKeysOnly is YES, searches only for keys whose secret part is
 * available.
 * 
 * This call also resets any pending key listing operation.
 * 
 * Can raise a #GPGException, even during enumeration.
"*/
{
    return [[[GPGKeyEnumerator alloc] initForContext:self searchPattern:searchPattern secretKeysOnly:secretKeysOnly] autorelease];
}

- (NSEnumerator *) trustListEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
/*"
 * Returns an enumerator of #GPGTrustItem instances.
 * 
 * searchPattern is a GnuPG %{user ID}. searchPattern cannot be nil nor empty.
 * 
 * Can raise a #GPGException, even during enumeration.
"*/
{
    return [[[GPGTrustItemEnumerator alloc] initForContext:self searchPattern:searchPattern maximumLevel:maxLevel] autorelease];
}

@end


@implementation GPGContext(GPGExtended)

- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients
/*"
 * Can raise a #GPGException.
"*/
{
    GpgmeData	outputData;
    GpgmeError	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_encrypt(_context, [recipients gpgmeRecipients], [inputData gpgmeData], outputData);
    if(anError != GPGME_No_Error){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGData *) decryptedData:(GPGData *)inputData
/*"
 * Can raise a #GPGException.
"*/
{
    GpgmeData	outputData;
    GpgmeError	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_decrypt(_context, [inputData gpgmeData], outputData);
    if(anError != GPGME_No_Error){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode
/*"
 * Data will be signed using either the default key or the ones defined in
 * context.
 * 
 * Note that settings done by #{-setUsesArmor:} and #{-setUsesTextMode:} are ignored for
 * mode #GPGSignatureModeClear.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeData	outputData;
    GpgmeError	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_sign(_context, [inputData gpgmeData], outputData, mode);
    if(anError != GPGME_No_Error){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGData *) exportedKeysForRecipients:(GPGRecipients *)recipients
/*"
 * Returns recipients public keys, wrapped in a #GPGData instance.
 * 
 * Keys are exported from standard pubring file.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeData	outputData;
    GpgmeError	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_export(_context, [recipients gpgmeRecipients], outputData);
    if(anError != GPGME_No_Error){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

@end


@implementation GPGContext(GPGInternals)

- (GpgmeCtx) gpgmeContext
{
    return _context;
}

@end


@implementation GPGSignerEnumerator

- (id) initForContext:(GPGContext *)newContext
{
    if(self = [self init]){
        // We retain newContext, to avoid it to be released before we are finished
        context = [newContext retain];
    }

    return self;
}

- (void) dealloc
{
    [context release];

    [super dealloc];
}

- (id) nextObject
{
    GpgmeKey	aKey = gpgme_signers_enum([context gpgmeContext], index);
    GPGKey		*returnedKey;

    if(aKey == NULL)
        return nil;
    index++;
    // Returned signer has already been retained by call gpgme_signers_enum(),
    // and calling -[GPGKey initWithInternalRepresentation:] retains it
    // too => we need to release it once.
    returnedKey = [[GPGKey alloc] initWithInternalRepresentation:aKey];
    gpgme_key_unref(aKey);
    
    return [returnedKey autorelease];
}

@end


@implementation GPGKeyEnumerator

- (id) initForContext:(GPGContext *)newContext searchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly
{
    if(self = [self init]){
        GpgmeError	anError;
        const char	*aPattern = (searchPattern != nil ? [searchPattern UTF8String]:NULL);

        anError = gpgme_op_keylist_start([newContext gpgmeContext], aPattern, secretKeysOnly);

        if(anError != GPGME_No_Error){
            [self release];
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        }
        else
            // We retain newContext, to avoid it to be released before we are finished
            context = [newContext retain];
    }

    return self;
}

- (void) dealloc
{
    [context release];

    [super dealloc];
}

- (id) nextObject
{
    GpgmeKey	aKey;
    GpgmeError	anError = gpgme_op_keylist_next([context gpgmeContext], &aKey);

    if(anError == GPGME_EOF)
        return nil;
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aKey != NULL, @"### Returned key is NULL, but no error?!");

    return [[[GPGKey alloc] initWithInternalRepresentation:aKey] autorelease];
}

@end


@implementation GPGTrustItemEnumerator

- (id) initForContext:(GPGContext *)newContext searchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
{
    if(self = [self init]){
        GpgmeError	anError;
        const char	*aPattern = (searchPattern != nil ? [searchPattern UTF8String]:NULL);

        anError = gpgme_op_trustlist_start([newContext gpgmeContext], aPattern, maxLevel);

        if(anError != GPGME_No_Error){
            [self release];
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        }
        else
            // We retain newContext, to avoid it to be released before we are finished
            context = [newContext retain];
    }

    return self;
}

- (void) dealloc
{
    [context release];

    [super dealloc];
}

- (id) nextObject
{
    GpgmeTrustItem	aTrustItem;
    GpgmeError		anError = gpgme_op_trustlist_next([context gpgmeContext], &aTrustItem);

    // Q: Does it really return a GPGME_EOF?
    // Answer from Werner: "It should, but well I may have to change things. Don't spend too much time on it yet."
    if(anError == GPGME_EOF)
        return nil;

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aTrustItem != NULL, @"### Returned trustItem is NULL, but no error?!");

    return [[[GPGTrustItem alloc] initWithInternalRepresentation:aTrustItem] autorelease];
}

@end


// We need to write this fake implementation (not compiled!)
// just to force autodoc to take our comments in account!
#ifdef FAKE_IMPLEMENTATION_FOR_AUTODOC
@implementation NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForDescription:(NSString *)description userInfo:(NSMutableDictionary *)userInfo
/*"
 * Description can be used as a prompt text (BUG: not yet localized).
 * userInfo can be used to store contextual information. It is passed from one call to
 * another with the values you put into. By default it is empty.
"*/
{
}
- (void) context:(GPGContext *)context progressingWithDescription:(NSString *)what type:(int)type current:(int)current total:(int)total
/*"
 * current is the amount done and total is amount to be done; a
 * total of 0 indicates that the total amount is not known. 100/100 may be
 * used to detect the end of operation.
 *
 * type is the letter printed during key generation.
"*/
{
}
@end
#endif

