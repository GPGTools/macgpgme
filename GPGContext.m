//
//  GPGContext.m
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

NSString	* const GPGKeyringChangedNotification = @"GPGKeyringChangedNotification";
NSString	* const GPGContextKey = @"GPGContextKey";

NSString	* const GPGProgressNotification = @"GPGProgressNotification";


@interface GPGSignerKeyEnumerator : NSEnumerator
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
 * All cryptographic operations in GPGME are performed within a context,
 * which contains the internal state of the operation as well as
 * configuration parameters. By using several contexts you can run
 * several cryptographic operations in parallel, with different configuration.
 *
 * UserID search patterns (for OpenPGP protocol):
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

static void progressCallback(void *object, const char *description, int type, int current, int total);

- (id) init
/*"
 * Designated initializer.
 * Creates a new context used to hold the configuration, status and result of cryptographic operations.
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
    gpgme_set_progress_cb(_context, progressCallback, self);

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

- (NSString *) notationsAsXMLString
/*"
 * If there are notation data available from the last signature check, this
 * method may be used to return these notation data as a string. The string
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
 * Returns whether context uses %{ASCII armor} or not. Default value is NO.
"*/
{
    return gpgme_get_armor(_context) != 0;
}

- (void) setUsesTextMode:(BOOL)mode
/*"
 * Enables or disables the use of the special %{text mode}. %{Text mode} is for
 * example used for MIME (RFC2015) signatures; note that the updated
 * RFC 3156 mandates that the mail user agent does some preparations
 * so that %{text mode} is not needed anymore.
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

- (void) setKeyListMode:(int)mask
/*"
 * Changes the default behaviour of the key listing methods.
 * The value in mask is a bitwise-or combination of one or multiple bit values
 * like #GPGKeyListModeLocal and #GPGKeyListModeExtern.
 *
 * At least #GPGKeyListModeLocal or #GPGKeyListModeExtern must be specified.
 * For future binary compatibility, you should get the current mode with #{-keyListMode}
 * and modify it by setting or clearing the appropriate bits, and then using
 * that calculated value in #{-setKeyListMode:}. This will leave all other bits
 * in the mode value intact (in particular those that are not used in the
 * current version of the library).
 *
 * Raises a #GPGException with name #GPGErrorInvalidValue in case mask is not a valid mode.
"*/
{
    GpgmeError	anError = gpgme_set_keylist_mode(_context, mask);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (int) keyListMode
/*"
 * Returns the current key listing mode of the context.
 * This value can then be modified and used in a subsequent #setKeyListMode: invocation
 * to only affect the desired bits (and leave all others intact).
 *
 * #GPGKeyListModeLocal is the default mode.
"*/
{
    int	mask = gpgme_get_keylist_mode(_context);

    NSAssert(mask != 0, @"_context is not a valid pointer");

    return mask;
}

- (void) setProtocol:(GPGProtocol)protocol
/*"
 * Sets the protocol and thus the crypto engine to be used by the context.
 * All crypto operations will be performed by the crypto engine configured for that protocol.
 *
 * Currently, the OpenPGP and the CMS protocols are supported.
 * A new context uses the OpenPGP engine by default.
 *
 * Setting the protocol with #{-setProtocol:} does not check
 * if the crypto engine for that protocol is available and installed correctly.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_set_protocol(_context, protocol);
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSString *) statusAsXMLString
/*"
 * Returns information about the last operation, as an XML string.
 * Returns nil if there is no previous
 * operation available or the operation has not yet finished.
 *
 * Here is a sample information that might be returned:
 *
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
 *
 * Currently the only operations that return additional information
 * are encrypt and sign.
"*/
#warning See gpgme.c for more info on format
// We should provide a class GPGContextStatus whose instances
// would contain the parsed information
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

static const char *passphraseCallback(void *object, const char *description, void **r_hd)
{
#if 1
    NSString	*aDescription;
    NSString	*aPassphrase;

    NSCAssert(r_hd != NULL, @"### passphraseCallback's r_hd is NULL?!");
    if(description == NULL){
        // We can now release resources associated with returned value
        if(*r_hd != NULL){
            [(*((NSMutableDictionary **)r_hd)) release];
            *r_hd = NULL;
        }
        
        return NULL;
    }
    aDescription = [NSString stringWithUTF8String:description];

    if(*r_hd == NULL)
        *r_hd = [[NSMutableDictionary alloc] initWithObjectsAndKeys:[NSMutableDictionary dictionary], @"userInfo", nil];

    aPassphrase = [((GPGContext *)object)->_passphraseDelegate context:((GPGContext *)object) passphraseForDescription:aDescription userInfo:[(*((NSMutableDictionary **)r_hd)) objectForKey:@"userInfo"]];

    if(aPassphrase == nil)
        return NULL;
    else{
        // We cannot simply pass [aPassphrase UTF8String], because
        // the buffer is autoreleased!!!
        const char	*aCString = [aPassphrase UTF8String];
        NSData		*passphraseAsData = [NSData dataWithBytes:aCString length:strlen(aCString) + 1];

        [(*((NSMutableDictionary **)r_hd)) setObject:passphraseAsData forKey:@"passphraseAsData"];

        return [passphraseAsData bytes];
    }
#else
    // Future implementation
    // Currently it cannot work, because libgpgme doesn't support
    // searching for a key  at this time, even in a new context.
    NSString	*aDescription, *aPattern;
    NSString	*aPassphrase;
    NSArray		*keys;
    BOOL		tryAgain;
    GPGContext	*keySearchContext;

    NSCAssert(r_hd != NULL, @"### passphraseCallback's r_hd is NULL?!");
    if(description == NULL){
        // We can now release resources associated with returned value
        if(*((void **)r_hd) != NULL){
            [(*((id *)r_hd)) release];
            *((void **)r_hd) = NULL;
        }
        
        return NULL;
    }
    aDescription = [NSString stringWithUTF8String:description];
    // Description format: currently on 3 lines
    // ENTER or TRY_AGAIN
    // keyID userID
    // keyID keyID algo
    tryAgain = [aDescription hasPrefix:@"TRY_AGAIN"];

    aPattern = [@"0x" stringByAppendingString:[[[[aDescription componentsSeparatedByString:@"\n"] objectAtIndex:1] componentsSeparatedByString:@" "] objectAtIndex:0]];
    keySearchContext = [[GPGContext alloc] init];
    keys = [[keySearchContext keyEnumeratorForSearchPattern:aPattern secretKeysOnly:YES] allObjects];
    [keySearchContext release];
    NSCAssert1([keys count] < 2, @"### More than one key for search pattern '%@'", aPattern);

    aPassphrase = [((GPGContext *)object)->_passphraseDelegate context:((GPGContext *)object) passphraseForKey:[keys lastObject] again:tryAgain];

    if(aPassphrase == nil)
        return NULL;
    else{
        // We cannot simply pass [aPassphrase UTF8String], because
        // the buffer is autoreleased!!!
        NSData	*passphraseAsData = [[aPassphrase dataUsingEncoding:NSUTF8StringEncoding] retain];

        if(*((void **)r_hd) == NULL)
            (*((id *)r_hd)) = passphraseAsData;
        else{
            [(*((id *)r_hd)) release];
            (*((id *)r_hd)) = passphraseAsData;
        }

        return [passphraseAsData bytes];
    }
#endif
}

static void progressCallback(void *object, const char *description, int type, int current, int total)
{
    // The <type> parameter is the letter printed during key generation 
    NSString	*aDescription = nil;
    unichar		typeChar = type;

    if(description != NULL)
        aDescription = [NSString stringWithUTF8String:description];
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGProgressNotification object:object userInfo:[NSDictionary dictionaryWithObjectsAndKeys:[NSString stringWithCharacters:&typeChar length:1], @"type", [NSNumber numberWithInt:current], @"current", [NSNumber numberWithInt:total], @"total", aDescription, @"description", nil]];
    // Note that if aDescription is nil, it will not be put into dictionary (ends argument list).
}

- (void) setPassphraseDelegate:(id)delegate
/*"
 * This methods allows a delegate to be used to pass a passphrase
 * to the engine. For OpenPGP, the preferred way to handle this is by using the gpg-agent, but
 * because that beast is not ready for real use, you can use this passphrase
 * thing.
 *
 * Not all crypto engines require this callback to retrieve the passphrase.
 * It is better if the engine retrieves the passphrase from a trusted agent (a daemon process),
 * rather than having each user to implement their own passphrase query.
 *
 * Delegate must respond to #context:passphraseForDescription:userInfo:.
 * Delegate is not retained.
 *
 * The user can disable the use of a passphrase callback by calling
 * #{-setPassphraseDelegate:} with nil as argument.
"*/
{
    NSParameterAssert(delegate == nil || [delegate respondsToSelector:@selector(context:passphraseForDescription:userInfo:)]);
    _passphraseDelegate = delegate; // We don't retain delegate
    if(delegate == nil)
        gpgme_set_passphrase_cb(_context, NULL, NULL);
    else
        gpgme_set_passphrase_cb(_context, passphraseCallback, self);
}

- (id) passphraseDelegate
/*"
 * Returns the delegate providing the passphrase. Initially nil.
"*/
{
    return _passphraseDelegate;
}

- (void) clearSignerKeys
/*"
 * Remove the list of signers from the context.
 *
 * Every context starts with an empty list.
"*/
{
    gpgme_signers_clear(_context);
    // Note that it also releases references to keys.
}

- (void) addSignerKey:(GPGKey *)key
/*"
 * Adds key to the list of signers in the context.
 *
 * Note that key is not retained.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError;

    NSParameterAssert(key != nil);

    anError = gpgme_signers_add(_context, [key gpgmeKey]);
    // It also acquires a reference to the key
    // => no need to retain the key
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSEnumerator *) signerKeyEnumerator
/*"
 * Returns an enumerator of #GPGKey instances, from the list of signers.
"*/
{
    return [[[GPGSignerKeyEnumerator alloc] initForContext:self] autorelease];
}

@end


@implementation GPGContext(GPGAsynchronousOperations)

- (void) cancelOperation
/*"
 * Tries to cancel the pending operation. It is not guaranteed that it will work under
 * under all circumstances. Its current primary purpose is to prevent
 * asking for a passphrase again in the passphrase callback.
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
 *
 * Can raise a #GPGException which reflects the termination status
 * of the operation (in case of error). The exception userInfo dictionary contains
 * the context (under #GPGContextKey key) which terminated with the error.
"*/
{
    GpgmeError	anError = GPGME_No_Error;
    GpgmeCtx	returnedCtx = gpgme_wait(NULL, &anError, hang);
    GPGContext	*newContext;

    if(anError != GPGME_No_Error){
        // Returns an existing context
        newContext = [[GPGContext alloc] initWithInternalRepresentation:returnedCtx];
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:[newContext autorelease] forKey:GPGContextKey]] raise];
    }

    if(returnedCtx != NULL){
        // Returns an existing context
        newContext = [[GPGContext alloc] initWithInternalRepresentation:returnedCtx];

        return [newContext autorelease];
    }
    else
        return nil;
}

- (BOOL) wait:(BOOL)hang
/*"
 * Continues the pending operation within the context.
 * In particular, it ensures the data exchange between
 * GPGME and the crypto backend and watches over the run time
 * status of the backend process.
 *
 * If hang is YES the method does not return until the operation
 * is completed or cancelled. Otherwise the method will not block
 * for a long time.
 *
 * If hang is YES, a #GPGIdleNotification may be posted.
 *
 * Returns YES if there is a finished request for context or NO if hang is NO
 * and no request (for context) has finished.
 *
 * Can raise a #GPGException which reflects the termination status
 * of the operation, in case of error.
"*/
{
    GpgmeError	anError = GPGME_No_Error;
    GpgmeCtx	returnedCtx = gpgme_wait(_context, &anError, hang);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    
    if(returnedCtx == _context)
        return YES;
    else
        return (returnedCtx != NULL);
}

@end


@implementation GPGContext(GPGSynchronousOperations)

- (GPGData *) decryptedData:(GPGData *)inputData
/*"
 * Decrypts the ciphertext in the inputData and returns the plain data.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to decrypt.}
 * _{GPGErrorDecryptionFailed  inputData is not a valid cipher text.}
 * _{GPGErrorNoPassphrase      The passphrase for the secret key could not be retrieved.}
 * Others exceptions could be raised too.
"*/
{
#warning BUG: does not raise any exception if no valid passphrase is given
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

- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData
/*"
 * Performs a signature check on the %detached signature given in signatureData (plaintext).
 * Returns the result of this operation, which can take these
 * values:
 *  _{GPGSignatureStatusNone         No status - should not happen.}
 *  _{GPGSignatureStatusGood         The signature is valid.}
 *  _{GPGSignatureStatusBad          The signature is not valid.}
 *  _{GPGSignatureStatusNoKey        The signature could not be checked due to a missing key.}
 *  _{GPGSignatureStatusNoSignature  This is not a signature.}
 *  _{GPGSignatureStatusError        Due to some other error the check could not be done.}
 *  _{GPGSignatureStatusDifferent    There is more than 1 signature and they have not the same status.}
 * 
 * If result is #GPGSignatureStatusDifferent or there are more than one
 * signature, use #{-statusOfSignatureAtIndex:creationDate:fingerprint:} to get
 * all signatures statuses.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to verify.}
 * Others exceptions could be raised too.
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
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to verify.}
 * Others exceptions could be raised too.
"*/
{
    GPGSignatureStatus	returnedStatus;
    GpgmeError			anError = gpgme_op_verify(_context, [signedData gpgmeData], NULL, &returnedStatus);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return returnedStatus;
}

- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerprint:(NSString **)fingerprintPtr
/*"
 * Returns information about a signature after #{-verifySignedData:},
 * #{-verifySignatureData:againstData:} or #{-decryptedData:signatureStatus:}
 * has been called. A single detached signature can contain signatures
 * by more than one key. index specifies which signature's information
 * should be retrieved, starting from 0.
 *
 * Returns #GPGSignatureStatusNone if there are no results yet, or there was a
 * verification error, or there is no signature at index index. creationDatePtr
 * and fingerprintPtr return the creation time stamp and the fingerprint of the
 * key which signed the plaintext, if not NULL.
"*/
{
    GPGSignatureStatus	returnedStatus;
    time_t				aTime;
    const char			*aCString = gpgme_get_sig_status(_context, index, &returnedStatus, &aTime);

    if(aCString == NULL)
        // No results yet or verification error or out-of-bounds
        returnedStatus = GPGSignatureStatusNone;
    else{
        if(fingerprintPtr != NULL)
        	*fingerprintPtr = [NSString stringWithUTF8String:aCString];
    
        if(creationDatePtr != NULL){
#warning Are we sure that localtime() uses the same timeZone as [NSTimeZone localTimeZone]?
            struct tm	*aTimeStruct = localtime(&aTime);
    
            *creationDatePtr = [NSCalendarDate dateWithYear:(1900 + aTimeStruct->tm_year) month:(aTimeStruct->tm_mon + 1) day:aTimeStruct->tm_mday hour:aTimeStruct->tm_hour minute:aTimeStruct->tm_min second:aTimeStruct->tm_sec timeZone:[NSTimeZone localTimeZone]];
        }
    }

    return returnedStatus;
}

- (GPGKey *) keyOfSignatureAtIndex:(int)index
/*"
 * Returns the key which was used to check the signature after #{-verifySignedData:},
 * #{-verifySignatureData:againstData:} or #{-decryptedData:signatureStatus:}
 * has been called. A single detached signature can contain signatures
 * by more than one key. index specifies which signature's information
 * should be retrieved, starting from 0.
 * 
 * Returns nil if there is no signature at index index.
 * 
 * Can raise a #GPGException (except a #GPGErrorEOF).
"*/
{
    GpgmeKey	aGpgmeKey;
    GpgmeError	anError = gpgme_get_sig_key(_context, index, &aGpgmeKey);
    GPGKey		*key;
    
    if(anError == GPGME_EOF)
        return nil;

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aGpgmeKey != NULL, @"### No gpgmeKey but no error?!");
    
    key = [[GPGKey alloc] initWithInternalRepresentation:aGpgmeKey];
	// Key returned by gpgme_get_sig_key() has one reference;
    // Wrapper also takes a reference on it,
    // thus we can remove one reference, safely.
    gpgme_key_unref(aGpgmeKey);
    
    return [key autorelease];
}

- (GPGData *) decryptedData:(GPGData *)inputData signatureStatus:(GPGSignatureStatus *)statusPtr
/*"
 * Decrypts the ciphertext in inputData and returns it as plain.
 * If cipher contains signatures, they will be verified and
 * their combined status will be returned in statusPtr, if not NULL.
 * 
 * After the operation completed, #{-statusOfSignatureAtIndex:creationDate:fingerprint:}
 * and #{-keyOfSignatureAtIndex:} can be used to retrieve more information about the signatures.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to decrypt.}
 * _{GPGErrorDecryptionFailed  inputData is not a valid cipher text.}
 * _{GPGErrorNoPassphrase      The passphrase for the secret key could not be retrieved.}
 * Others exceptions could be raised too.
"*/
{
    GpgmeData	outputData;
    GpgmeError	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_decrypt_verify(_context, [inputData gpgmeData], outputData, statusPtr);
    if(anError != GPGME_No_Error){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode
/*"
 * Creates a signature for the text in inputData and returns either the signed data
 * or a detached signature, depending on the mode.
 * Data will be signed using either the default key or the ones defined in
 * context.
 * A signature can contain signatures by one or more keys.
 * The set of keys used to create a signatures is contained in the context,
 * and is applied to all following signing operations in the context
 * (until the set is changed).
 * 
 * Note that settings done by #{-setUsesArmor:} and #{-setUsesTextMode:} are ignored for
 * mode #GPGSignatureModeClear.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData        The signature could not be created.}
 * _{GPGErrorNoPassphrase  The passphrase for the secret key could not be retrieved.}
 * Others exceptions could be raised too.
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

- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients
/*"
 * Encrypts the plaintext in inputData for the recipients and
 * returns the ciphertext. The type of the ciphertext created is determined
 * by the %{ASCII armor} and %{text mode} attributes set for the context.
 *
 * One plaintext can be encrypted for several %recipients at the same time.
 * The list of %recipients is created independently of any context,
 * and then passed to the encryption operation.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoRecipients  recipients does not contain valid recipients.}
 * _{GPGErrorNoPassphrase  The passphrase for the secret key could not be retrieved.}
 * Others exceptions could be raised too.
"*/
{
#warning BUG: does not raise any exception if no recipient is trusted! (but it encrypts nothing)
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

- (GPGData *) exportedKeysForRecipients:(GPGRecipients *)recipients
/*"
 * Extracts the public keys of the user IDs in recipients and returns
 * them. The type of the public keys returned is determined by the %{ASCII armor}
 * attribute set for the context.
 * 
 * Keys are exported from standard key ring.
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

- (void) importKeyData:(GPGData *)keyData
/*"
 * Adds the keys in keyData to the key ring of the crypto engine used
 * by the context. The format of keydata content can be %{ASCII armored},
 * for example, but the details are specific to the crypto engine.
 * More information about the import is available with #{-statusAsXMLString}.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData  keydata is an empty buffer.}
 * Others exceptions could be raised too.
"*/
{
    GpgmeError	anError = gpgme_op_import(_context, [keyData gpgmeData]);
    // It would be nice if we could get imported keys in returned value...

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]];
}

#warning FIXME: gpgme_op_genkey() has no counterpart
#if 0
- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr
//- (void) generateKeyFromDictionary:(NSDictionary *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr
/*"
 * Generates a new key pair and puts it into the standard key ring if
 * both publicKeyPtr and secretKeyPtr are NULL. In this case
 * method returns immediately after starting the operation, and does not wait for
 * it to complete. If publicKeyPtr is not NULL, the newly created data object,
 * upon successful completion, will contain the public key. If secretKeyPtr
 * is not NULL, the newly created data object, upon successful completion,
 * will contain the secret key.
 *
 * Note that not all crypto engines support this interface equally.
 * GnuPG does not support publicKey and secretKeyPtr, they should be both NULL,
 * and the key pair will be added to the standard key ring.
 * GpgSM does only support publicKeyPtr, the secret key will be
 * stored by gpg-agent. GpgSM expects publicKeyPtr being not NULL.
 *
 * The params string specifies parameters for the key in XML format.
 * The details about the format of params are specific to the crypto engine
 * use by the context. Here's an example for #GnuPG as the crypto engine:
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
 * Here's an example for GpgSM as the crypto engine:
 * !{<GnupgKeyParms format="internal">
 *   Key-Type: RSA
 *   Key-Length: 1024
 *   Name-DN: C=de,O=g10 code,OU=Testlab,CN=Joe 2 Tester
 *   Name-Email: joe@@foo.bar
 * </GnupgKeyParms>}
 * Strings should be given in UTF-8 encoding. The format supportted for now
 * is "internal". The content of the !{<GnupgKeyParms>} container is passed
 * verbatim to GnuPG. Control statements (e.g. pubring) are not allowed.
 * Key is generated in standard secring/pubring files if both secretKeyPtr
 * and publicKeyPtr are NULL, else newly created key is returned but not stored
 * Currently cannot return generated secret/public keys.
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidValue  params is not a valid XML string.}
 * _{GPGErrorNotSupported  publicKeyPtr or secretKeyPtr is not NULL.}
 * _{GPGErrorGeneralError  No key was created by the engine.}
 * Others exceptions could be raised too.
"*/
{
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]];
}
#endif

- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret
/*"
 * Deletes the given key from the standard key ring of the crypto engine used by the context.
 * To delete a secret key along with the public key, allowSecret must be YES,
 * else only the public key is deleted.
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidKey  key could not be found in the key ring.}
 * _{GPGErrorConflict    Secret key for key is available, but allowSecret is NO.}
"*/
{
#warning BUG: it seems it doesn't work yet...
    GpgmeError	anError = gpgme_op_delete(_context, [key gpgmeKey], allowSecret);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]];
}

@end


@implementation GPGContext(GPGKeyManagement)

- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly
/*"
 * Returns an enumerator of #GPGKey instances. It starts a key listing operation inside the context;
 * the context will be busy until either all keys are received, or #{-stopKeyEnumeration} is invoked,
 * or the enumerator has been deallocated.
 * 
 * searchPattern is an engine specific expression that is used to limit the list to all keys
 * matching the pattern. searchPattern can be nil; in this case
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

- (void) stopKeyEnumeration
/*"
 * Ends the key listing operation and allows to use the context for some
 * other operation next. This is not an error to invoke that method
 * if there is no pending key listing operation.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_op_keylist_end(_context);

    // Let's ignore GPGME_No_Request which means that there is no
    // pending key listing operation.
    if(anError != GPGME_No_Error && anError != GPGME_No_Request)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSEnumerator *) trustItemEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
/*"
 * Returns an enumerator of #GPGTrustItem instances.
 * 
 * searchPattern contains an engine specific expression that is used to limit the list
 * to all trust items matching the pattern. It can not be the empty string or nil.
 *
 * maxLevel is currently ignored.
 *
 * Context will be busy until either all trust items are enumerated, or #{-stopTrustItemEnumeration} is invoked,
 * or the enumerator has been deallocated.
 * 
 * Can raise a #GPGException, even during enumeration.
"*/
{
    return [[[GPGTrustItemEnumerator alloc] initForContext:self searchPattern:searchPattern maximumLevel:maxLevel] autorelease];
}

- (void) stopTrustItemEnumeration
/*"
 * Ends the trustlist operation and allows to use the context for some
 * other operation next. This is not an error to invoke that method
 * if there is no pending trustlist operation.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_op_trustlist_end(_context);

    // Let's ignore GPGME_No_Request which means that there is no
    // pending keylist operation.
    if(anError != GPGME_No_Error && anError != GPGME_No_Request)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

@end


@implementation GPGContext(GPGInternals)

- (GpgmeCtx) gpgmeContext
{
    return _context;
}

@end


@implementation GPGSignerKeyEnumerator

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
    GpgmeKey	aKey = gpgme_signers_enum([context gpgmeContext], index); // Acquires a reference to the signers key with the specified index
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
    GpgmeError	anError = GPGME_No_Error;
    
    if(context != nil){
        anError= gpgme_op_keylist_end([context gpgmeContext]);
        [context release];
    }

    [super dealloc];

    // GPGME_No_Request error means that there was no pending request.
    // We can safely ignore this error here, because we don't know
    // when context has been freed.
    if(anError != GPGME_No_Error && anError != GPGME_No_Request)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (id) nextObject
{
    GpgmeKey	aKey;
    GpgmeError	anError;

    NSAssert(context != nil, @"### Enumerator is invalid now, because an exception was raised during enumeration.");
    anError = gpgme_op_keylist_next([context gpgmeContext], &aKey);
    if(anError == GPGME_EOF)
        return nil;
    
    if(anError != GPGME_No_Error){
        // We release and nullify context; we don't want another exception
        // being raised during -dealloc, as we call gpgme_op_keylist_end(). 
        [context release];
        context = nil;
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

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
    GpgmeError	anError = gpgme_op_trustlist_end([context gpgmeContext]);

    [context release];

    [super dealloc];

    // GPGME_No_Request error means that there was no pending request.
    // We can safely ignore this error here.
    if(anError != GPGME_No_Error && anError != GPGME_No_Request)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
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
 *
 * Currently, description has the following format: it is a 3 lines string.
 * -{1  ENTER or TRY_AGAIN}
 * -{2  keyID userID}
 * -{3  keyID keyID algo}
 *
 * #CAUTION:
 * Method will change in the future to context:passphraseForKey:again:, but currently you cannot ask
 * for a key during passphrase callback (limitation due to gpgme, as of 0.3.3).
"*/
{
}
@end
#endif

