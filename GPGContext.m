//
//  GPGContext.m
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

#import "GPGContext.h"
#import "GPGData.h"
#import "GPGExceptions.h"
#import "GPGInternals.h"
#import "GPGKey.h"
#import "GPGRecipients.h"
#import "GPGTrustItem.h"
#import <Foundation/Foundation.h>
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
{
    GpgmeError	anError = gpgme_new((GpgmeCtx *)&_internalRepresentation);

    if(anError != GPGME_No_Error){
        _internalRepresentation = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_internalRepresentation];

#warning We should also retain all objC resources created by ourself??
    // According to gpgme_new() documentation:
    // Create a new context to be used with most of the other GPGME
    // functions.  Use gpgme_release_context() to release all resources
    // Q: what are these resources??? Ask Werner...

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
{
    gpgme_cancel(_context);
}

+ (GPGContext *) waitOnAnyRequest:(BOOL)hang
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
{
    GpgmeCtx	returnedCtx = gpgme_wait(_context, hang);

    if(returnedCtx == _context)
        return YES;
    else
        return (returnedCtx != NULL);
}

- (NSString *) xmlNotation
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

- (void) setArmor:(BOOL)armor
{
    gpgme_set_armor(_context, armor);
}

- (void) setTextMode:(BOOL)mode
{
    gpgme_set_textmode(_context, mode);
}

- (void) setFastKeyListMode:(BOOL)mode
{
    gpgme_set_keylist_mode(_context, !!mode);
}

static const char *passphraseCallback(void *object, const char *description, void *r_hd)
{
    NSString	*aDescription;
    NSString	*aPassphrase;

    NSCAssert(r_hd != NULL, @"passphraseCallback's r_hd is NULL?!");
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
#warning What is this <type> parameter???
    NSString	*aDescription = nil;

    if(description != NULL)
        aDescription = [NSString stringWithUTF8String:description];
    [((GPGContext *)object)->_progressDelegate context:((GPGContext *)object) progressingWithDescription:aDescription type:type current:current total:total];
}

- (void) setPassphraseDelegate:(id)delegate
{
    NSParameterAssert(delegate == nil || [delegate respondsToSelector:@selector(context:passphraseForDescription:userInfo:)]);
    _passphraseDelegate = delegate; // We don't retain delegate
    if(delegate == nil)
        gpgme_set_passphrase_cb(_context, NULL, NULL);
    else
        gpgme_set_passphrase_cb(_context, passphraseCallback, self);
}

- (void) setProgressDelegate:(id)delegate
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
{
    GpgmeError	anError;

    NSParameterAssert(key != nil);

#warning Should we retain key?
    anError = gpgme_signers_add(_context, [key gpgmeKey]);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSEnumerator *) signerEnumerator
{
    return [[[GPGSignerEnumerator alloc] initForContext:self] autorelease];
}

- (GPGSignatureStatus) statusOfSignatureAtIndex:(int)index creationDate:(NSCalendarDate **)creationDatePtr fingerPrint:(NSString **)fingerPrintPtr
{
    GPGSignatureStatus	returnedStatus;
    time_t				aTime;
    const char			*aCString = gpgme_get_sig_status(_context, index, &returnedStatus, &aTime);

    if(fingerPrintPtr != NULL){
        if(aCString != NULL)
            *fingerPrintPtr = [NSString stringWithUTF8String:aCString];
        else
            *fingerPrintPtr = nil;
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
{
    GpgmeKey	aGpgmeKey;
    GpgmeError	anError = gpgme_get_sig_key(_context, index, &aGpgmeKey);

    if(anError == GPGME_EOF)
        return nil;

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aGpgmeKey != NULL, @"No gpgmeKey but no error?!");
    
    return [[[GPGKey alloc] initWithInternalRepresentation:aGpgmeKey] autorelease];
}

@end


@implementation GPGContext(GPGBasic)
#warning Functions gpgme_op_start_XXX have no counterpart...
@end


@implementation GPGContext(GPGNormalUsage)

- (GPGSignatureStatus) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData
{
    GPGSignatureStatus	returnedStatus;
    GpgmeError			anError = gpgme_op_verify(_context, [signatureData gpgmeData], [inputData gpgmeData], &returnedStatus);
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return returnedStatus;
}

- (GPGSignatureStatus) verifySignedData:(GPGData *)signedData
{
    GPGSignatureStatus	returnedStatus;
    GpgmeError			anError = gpgme_op_verify(_context, [signedData gpgmeData], NULL, &returnedStatus);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return returnedStatus;
}

- (void) importKeyData:(GPGData *)keyData
{
    GpgmeError	anError = gpgme_op_import(_context, [keyData gpgmeData]);
    // It would be nice if we could get imported keys in returned value...

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    // We could post a notification here...
}

#warning gpgme_op_genkey() has no counterpart
/*- (void) generateKeyWithXMLString:(NSString *)params secretKey:(GPGData **)secretKeyPtr publicKey:(GPGData **)publicKeyPtr
{
    // We could post a notification here...
}*/

- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret
{
    GpgmeError	anError = gpgme_op_delete(_context, [key gpgmeKey], allowSecret);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    // We could post a notification here...
}

@end


@implementation GPGContext(GPGKeyManagement)

- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly
{
    return [[[GPGKeyEnumerator alloc] initForContext:self searchPattern:searchPattern secretKeysOnly:secretKeysOnly] autorelease];
}

- (NSEnumerator *) trustListEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
{
    return [[[GPGTrustItemEnumerator alloc] initForContext:self searchPattern:searchPattern maximumLevel:maxLevel] autorelease];
}

@end


@implementation GPGContext(GPGExtended)

- (GPGData *) encryptedData:(GPGData *)inputData forRecipients:(GPGRecipients *)recipients
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

    NSAssert(aKey != NULL, @"Returned key is NULL, but no error?!");

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

#warning Does it really return a GPGME_EOF?
    if(anError == GPGME_EOF)
        return nil;

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aTrustItem != NULL, @"Returned trustItem is NULL, but no error?!");

    return [[[GPGTrustItem alloc] initWithInternalRepresentation:aTrustItem] autorelease];
}

@end
