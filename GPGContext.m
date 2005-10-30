//
//  GPGContext.m
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

#include <MacGPGME/GPGContext.h>
#include <MacGPGME/GPGData.h>
#include <MacGPGME/GPGExceptions.h>
#include <MacGPGME/GPGInternals.h>
#include <MacGPGME/GPGRemoteKey.h>
#include <MacGPGME/GPGKeyGroup.h>
#include <MacGPGME/GPGOptions.h>
#include <MacGPGME/GPGSignature.h>
#include <MacGPGME/GPGTrustItem.h>
#include <Foundation/Foundation.h>
#include <time.h> /* Needed for GNUstep */
#include <gpgme.h>


#define _context	((gpgme_ctx_t)_internalRepresentation)


NSString	* const GPGKeyringChangedNotification = @"GPGKeyringChangedNotification";
NSString	* const GPGContextKey = @"GPGContextKey";
NSString	* const GPGChangesKey = @"GPGChangesKey";

NSString	* const GPGProgressNotification = @"GPGProgressNotification";

NSString	* const GPGAsynchronousOperationDidTerminateNotification = @"GPGAsynchronousOperationDidTerminateNotification";

NSString	* const GPGNextKeyNotification = @"GPGNextKeyNotification";
NSString	* const GPGNextKeyKey = @"GPGNextKeyKey";

NSString	* const GPGNextTrustItemNotification = @"GPGNextTrustItemNotification";
NSString	* const GPGNextTrustItemKey = @"GPGNextTrustItemKey";


static NSMapTable	*_helperPerContext = NULL;
static NSLock		*_helperPerContextLock = nil;


enum {
    EncryptOperation          = 1 <<  0,
    SignOperation             = 1 <<  1,
    VerifyOperation           = 1 <<  2,
    DecryptOperation          = 1 <<  3,
    ImportOperation           = 1 <<  4,
    KeyGenerationOperation    = 1 <<  5,
    KeyListingOperation       = 1 <<  6,
    SingleKeyListingOperation = 1 <<  7,
    ExportOperation           = 1 <<  8,
    TrustItemListingOperation = 1 <<  9,
    KeyDeletionOperation      = 1 << 10,
    RemoteKeyListingOperation = 1 << 11,
    KeyDownloadOperation      = 1 << 12,
    KeyUploadOperation        = 1 << 13
}; // Values for _operationMask


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
- (id) initForContext:(GPGContext *)context searchPatterns:(NSArray *)searchPatterns secretKeysOnly:(BOOL)secretKeysOnly;
// Designated initializers
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


@interface GPGContext(Private)
- (NSDictionary *) _invalidKeysReasons:(gpgme_invalid_key_t)invalidKeys keys:(NSArray *)keys;
- (GPGKey *) _keyWithFpr:(const char *)fpr isSecret:(BOOL)isSecret;
- (GPGError) _importKeyDataFromServerOutput:(NSData *)result;
@end


@implementation GPGContext
/*"
 * All cryptographic operations in GPGME are performed within a context, which
 * contains the internal state of the operation as well as configuration
 * parameters. By using several contexts you can run several cryptographic
 * operations in parallel, with different configuration.
 *
 * #{UserID search patterns (for OpenPGP protocol):}
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
 *
 * You can attach arbitrary notation data to a signature. This information is
 * then available to the user when the signature is verified. Use method
 * #{-addSignatureNotationWithName:value:flags:} to set notation data to a 
 * signature the context will create.
"*/

static void progressCallback(void *object, const char *description, int type, int current, int total);

+ (void) initialize
{
    [super initialize];
    if(_helperPerContextLock == nil){
        _helperPerContextLock = [[NSLock alloc] init];
        _helperPerContext = NSCreateMapTable(NSObjectMapKeyCallBacks, NSObjectMapValueCallBacks, 3);
    }
}

- (id) init
/*"
 * Designated initializer. Creates a new context used to hold the
 * configuration, status and result of cryptographic operations.
 * 
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_ctx_t		aContext;
    gpgme_error_t	anError = gpgme_new(&aContext);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aContext];
    gpgme_set_progress_cb(aContext, progressCallback, self);
    _operationData = [[NSMutableDictionary allocWithZone:[self zone]] init];
    _signerKeys = [[NSMutableSet allocWithZone:[self zone]] init];

    return self;
}

- (void) dealloc
{
    gpgme_ctx_t	cachedContext = _context;

    if(_context != NULL){
        gpgme_set_passphrase_cb(_context, NULL, NULL);
        gpgme_set_progress_cb(_context, NULL, NULL);
    }
    [_operationData release];
    if(_userInfo != nil)
        [_userInfo release];
    [_signerKeys release];
    if(_engines != nil){
        NSEnumerator    *anEnum = [_engines objectEnumerator];
        GPGEngine       *anEngine;
        
        while((anEngine = [anEnum nextObject]))
            [anEngine invalidateContext];
        [_engines release];
    }

    [super dealloc];

    if(cachedContext != NULL)
        gpgme_release(cachedContext);
}

- (id) copyWithZone:(NSZone *)zone
/*"
 * Copies engine configurations.  
"*/
{
    GPGContext      *contextCopy = [[[self class] alloc] init];
    NSEnumerator    *engineEnum = [[self engines] objectEnumerator];
    GPGEngine       *anEngine;
    
    while(anEngine = [engineEnum nextObject]){
        NSEnumerator    *engineCopyEnum = [[contextCopy engines] objectEnumerator];
        GPGEngine       *anEngineCopy;
    
        while(anEngineCopy = [engineCopyEnum nextObject]){
            if([anEngineCopy engineProtocol] == [anEngine engineProtocol]){
                [anEngineCopy setExecutablePath:[anEngine executablePath]];
                [anEngineCopy setHomeDirectory:[anEngine homeDirectory]];
                break;
            }
        }
    }
    
    return contextCopy;
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
 * Enables or disables the use of the special %{text mode}. %{Text mode} is 
 * for example used for MIME (RFC2015) signatures; note that the updated
 * RFC 3156 mandates that the mail user agent does some preparations so that
 * %{text mode} is not needed anymore.
 *
 * This option is only relevant to the OpenPGP crypto engine, and ignored by
 * all other engines.
 * 
 * Default value is NO.
"*/
{
    gpgme_set_textmode(_context, mode);
}

- (BOOL) usesTextMode
/*"
 * Returns whether context uses %{text mode} or not. Default value is NO.
"*/
{
    return gpgme_get_textmode(_context) != 0;
}

- (void) setKeyListMode:(GPGKeyListMode)mask
/*"
 * Changes the default behaviour of the key listing methods. The value in mask
 * is a bitwise-or combination of one or multiple bit values like
 * #GPGKeyListModeLocal and #GPGKeyListModeExtern.
 *
 * At least #GPGKeyListModeLocal or #GPGKeyListModeExtern must be specified.
 * For future binary compatibility, you should get the current mode with
 * #{-keyListMode} and modify it by setting or clearing the appropriate bits, 
 * and then using that calculated value in #{-setKeyListMode:}. This will 
 * leave all other bits in the mode value intact (in particular those that are 
 * not used in the current version of the library).
 *
 * Raises a #GPGException with name #GPGErrorInvalidValue in case mask is not
 * a valid mode.
"*/
{
    gpgme_error_t	anError = gpgme_set_keylist_mode(_context, mask);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (GPGKeyListMode) keyListMode
/*"
 * Returns the current key listing mode of the context. This value can then be
 * modified and used in a subsequent #setKeyListMode: invocation to only
 * affect the desired bits (and leave all others intact).
 *
 * #GPGKeyListModeLocal is the default mode.
"*/
{
    gpgme_keylist_mode_t	mask = gpgme_get_keylist_mode(_context);

    NSAssert(mask != 0, @"_context is not a valid pointer");

    return mask;
}

- (void) setProtocol:(GPGProtocol)protocol
/*"
 * Sets the protocol and thus the crypto engine to be used by the context. All
 * crypto operations will be performed by the crypto engine configured for
 * that protocol.
 *
 * Currently, the OpenPGP and the CMS protocols are supported. A new context
 * uses the OpenPGP engine by default.
 *
 * Setting the protocol with #{-setProtocol:} does not check if the crypto
 * engine for that protocol is available and installed correctly.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_error_t	anError = gpgme_set_protocol(_context, protocol);
    
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (GPGProtocol) protocol
/*"
 * Returns the protocol currently used by the context.
"*/
{
    gpgme_protocol_t	protocol = gpgme_get_protocol(_context);

    return protocol;
}

static gpgme_error_t passphraseCallback(void *object, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd)
{
    NSString		*aPassphrase = nil;
    NSArray			*keys = nil;
    gpgme_error_t	error = GPG_ERR_NO_ERROR;
    NSFileHandle	*resultFileHandle;

    // With a PGP key we have:
    // passphrase_info = "keyID (sub?)keyID algo 0"
    // uid_hint = "keyID userID"
    // Note that if keyID has been thrown away, we still have this info,
    // because gpg will try all secret keys.
    // For symmetric encryption and decryption we have:
    // passphrase_info = "3 3 2" = symmetricEncryptionAlgo ? ?
    // uid_hint = NULL

    if(uid_hint != NULL){
        // In case of symmetric encryption, no key is needed
        NSString	*aPattern = GPGStringFromChars(passphrase_info);
        GPGContext	*keySearchContext = nil;

		NS_DURING
			keySearchContext = [((GPGContext *)object) copy];
			// Do NOT use the whole uid_hint, because it causes problems with
			// uids that have ISOLatin1 data (instead of UTF8), and can also
			// lead to "ambiguous name" error. Use only the keyID, taken from
			// the passphrase_info.
			aPattern = [aPattern substringToIndex:[aPattern rangeOfString:@" "].location];
			keys = [[keySearchContext keyEnumeratorForSearchPattern:aPattern secretKeysOnly:YES] allObjects];
			[keySearchContext stopKeyEnumeration];
			[keySearchContext release];
		NS_HANDLER
			[keySearchContext release];
		NS_ENDHANDLER

        NSCAssert2([keys count] == 1, @"### No key or more than one key (%d) for search pattern '%@'", [keys count], aPattern);
    }

    NS_DURING
        aPassphrase = [((GPGContext *)object)->_passphraseDelegate context:((GPGContext *)object) passphraseForKey:[keys lastObject] again:!!prev_was_bad];
    NS_HANDLER
        if([[localException name] isEqualToString:GPGException]){
            error = [[[localException userInfo] objectForKey:GPGErrorKey] intValue];
            aPassphrase = @"";
        }
        else
            [localException raise];
    NS_ENDHANDLER

    if(aPassphrase == nil){
        // Cancel operation
        aPassphrase = @"";
        error = gpgme_error(GPG_ERR_CANCELED);
    }

    resultFileHandle = [[NSFileHandle alloc] initWithFileDescriptor:fd];
    [resultFileHandle writeData:[[aPassphrase stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
    [resultFileHandle release];

    return error;
}

- (void) postNotificationInMainThread:(NSNotification *)notification
{
    [[NSNotificationCenter defaultCenter] postNotification:notification];
}

static void progressCallback(void *object, const char *description, int type, int current, int total)
{
    // The <type> parameter is the letter printed during key generation 
    NSString			*aDescription = nil;
    unichar				typeChar = type;
    NSNotification		*aNotification;
    GPGContext			*aContext = (GPGContext *)object;
    NSAutoreleasePool	*localAP = [[NSAutoreleasePool alloc] init];

    if(description != NULL)
        aDescription = [NSString stringWithUTF8String:description];
    aNotification = [NSNotification notificationWithName:GPGProgressNotification object:aContext userInfo:[NSDictionary dictionaryWithObjectsAndKeys:[NSString stringWithCharacters:&typeChar length:1], @"type", [NSNumber numberWithInt:current], @"current", [NSNumber numberWithInt:total], @"total", aDescription, @"description", nil]];
    // Note that if aDescription is nil, it will not be put into dictionary (ends argument list).
    [aContext performSelectorOnMainThread:@selector(postNotificationInMainThread:) withObject:aNotification waitUntilDone:NO];
    [localAP release];
}

- (void) setPassphraseDelegate:(id)delegate
/*"
 * This methods allows a delegate to be used to pass a passphrase to the
 * engine. For OpenPGP, the preferred way to handle this is by using the
 * gpg-agent, but because that beast is not ready for real use, you can use 
 * this passphrase thing.
 *
 * Not all crypto engines require this callback to retrieve the passphrase.
 * It is better if the engine retrieves the passphrase from a trusted agent
 * (a daemon process), rather than having each user to implement their own
 * passphrase query. Some engines do not even support an external passphrase
 * callback at all, in this case a GPGException with error code 
 * GPGErrorNotSupported is returned.
 *
 * Delegate must respond to #{context:passphraseForKey:again:}. Delegate is
 * not retained.
 *
 * The user can disable the use of a passphrase callback by calling
 * #{-setPassphraseDelegate:} with nil as argument.
"*/
{
    NSParameterAssert(delegate == nil || [delegate respondsToSelector:@selector(context:passphraseForKey:again:)]);
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
    [_signerKeys removeAllObjects];
}

- (void) addSignerKey:(GPGKey *)key
/*"
 * Adds key to the list of signers in the context. key is retained.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_error_t	anError;

    NSParameterAssert(key != nil);

    anError = gpgme_signers_add(_context, [key gpgmeKey]);
    // It also acquires a reference to the key
    // => no need to retain the key
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    else
        // Now we also retain keys to have a more consistent ObjC API.
        [_signerKeys addObject:key];
}

- (NSEnumerator *) signerKeyEnumerator
/*"
 * Returns an enumerator of #GPGKey instances, from the list of signers.
"*/
{
    return [[[GPGSignerKeyEnumerator alloc] initForContext:self] autorelease];
}

- (NSArray *) signerKeys
/*"
 * Convenience method. Returns [[self signerKeyEnumerator] allObjects].
"*/
{
    return [[self signerKeyEnumerator] allObjects];
}

- (void) setCertificatesInclusion:(int)includedCertificatesNumber
/*"
 * Specifies how many certificates should be included in an S/MIME signed
 * message. By default, only the sender's certificate is included. The
 * possible values of includedCertificatesNumber are:
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
 *
 * Values of includedCertificatesNumber smaller than -2 are undefined.
 *
 * This option is only relevant to the CMS crypto engine, and ignored by all
 * other engines.
"*/
{
    gpgme_set_include_certs(_context, includedCertificatesNumber);
}

- (int) certificatesInclusion
/*"
 * Returns the number of certificates to include in an S/MIME message.
"*/
{
    return gpgme_get_include_certs(_context);
}

- (NSDictionary *) operationResults
/*"
 * Returns a dictionary containing results of last operation on context.
 * Contents of the dictionary depends on last operation type (signing,
 * decrypting, etc.), and method can be called even if last operation failed
 * and raised an exception: -operationResults could return partial valid data.
 * Dictionary always contains the result error of the last operation under key
 * #GPGErrorKey.
 *
 * If last operation was an encryption operation, dictionary can contain:
 * _{@"keyErrors"  Dictionary containing GPGKey instances as keys, and 
 *                 GPGError NSNumber instances as values.}
 * _{@"cipher"     GPGData instance with encrypted data; only valid keys were
 *                 used.}
 *
 * If last operation was a signing operation, dictionary can contain:
 * _{@"signedData"     GPGData instance with signed data; only valid secret 
 *                     keys were used.}
 * _{@"newSignatures"  An NSArray of GPGSignature instances.}
 * _{@"keyErrors"      Dictionary containing GPGKey instances as keys, and
 *                     GPGError NSNumber instances as values.}
 *
 * If last operation was a verification operation, dictionary can contain:
 * _{@"signatures"  An NSArray of GPGSignature instance. Same result is
 *                  returned by #{-signatures}.}
 * _{@"filename"    The original filename of the plaintext message, if 
 *                  available.}
 *
 * If last operation was a decryption operation, dictionary can contain:
 * _{@"unsupportedAlgorithm"  An NSString instance describing the algorithm
 *                            used for encryption, which is not known by the
 *                            engine for decryption.}
 * _{@"wrongKeyUsage"         A boolean result as a NSNumber instance indicating
 *                            that the key should not have been used for
 *                            encryption.}
 * _{@"filename"              The original filename of the plaintext message, if 
 *                            available.}
 * _{@"keyErrors"             Dictionary containing GPGKey or GPGRemoteKey 
 *                            instances as keys, and GPGError NSNumber
 *                            instances as values.}
 *
 * If last operation was an import operation, dictionary can contain:
 * _{@"keys"                     Dictionary whose keys are #GPGKey instances,
 *                               and values are also dictionaries; these can
 *                               contain a key-value pair 'error' with an
 *                               #GPGError, and a key-value pair 'status' with
 *                               a #GPGImportStatus (bit-field)}
 * _{@"consideredKeyCount"       Total number of considered keys}
 * _{@"keysWithoutUserIDCount"   Number of keys without user ID}
 * _{@"importedKeyCount"         Total number of imported keys}
 * _{@"importedRSAKeyCount"      Number of imported RSA keys}
 * _{@"unchangedKeyCount"        Number of unchanged keys}
 * _{@"newUserIDCount"           Number of new user IDs}
 * _{@"newSubkeyCount"           Number of new subkeys}
 * _{@"newSignatureCount"        Number of new signatures}
 * _{@"newRevocationCount"       Number of new revocations}
 * _{@"readSecretKeyCount"       Total number of secret keys read}
 * _{@"importedSecretKeyCount"   Number of imported secret keys}
 * _{@"unchangedSecretKeyCount"  Number of unchanged secret keys}
 * _{@"skippedNewKeyCount"       Number of new keys skipped}
 * _{@"notImportedKeyCount"      Number of keys not imported}
 *
 * If last operation was a key generation operation, dictionary can contain:
 * _{#GPGChangesKey  See #GPGKeyringChangedNotification notification for more
 *                   information about #GPGChangesKey.}
 *
 * If last operation was a key deletion operation, dictionary can contain:
 * _{@"deletedKeyFingerprints"  An NSArray of NSString instances representing
 *                              the fingerprints of deleted keys.}
 *
 * If last operation was a key enumeration operation, dictionary can contain:
 * _{@"truncated"  A boolean result as a NSNumber instance indicating whether
 *                 all matching keys were listed or not.}
 *
 * If last operation was a remote key search operation, dictionary can
 * contain:
 * _{@"keys"             An array of #GPGRemoteKey instances: these are not
 *                       usable keys, they contain no other information than
 *                       keyID, algorithm, algorithmDescription, length, creationDate,
 *                       expirationDate, userIDs, isKeyRevoked; userIDs are
 *                       also #GPGRemoteUserID instances that contain no other
 *                       information than userID. Returned information depends
 *                       on servers.}
 * _{@"hostName"         Contacted server's host name}
 * _{@"port"             Port used to contact server, if not default one}
 * _{@"protocol"         Protocol used to contact server (ldap, x-hkp, hkp, 
 *                       http, finger)}
 * _{@"options"          Options used to contact server}
 *
 * If last operation was a key download operation, dictionary can contain:
 * _{@"hostName"         Contacted server's host name}
 * _{@"port"             Port used to contact server, if not default one}
 * _{@"protocol"         Protocol used to contact server (ldap, x-hkp, hkp, 
 *                       http, finger)}
 * _{@"options"          Options used to contact server}
 * and additional results from the import operation.
"*/
{
    NSMutableDictionary	*operationResults = [NSMutableDictionary dictionary];
    NSObject			*anObject;

    anObject = [_operationData objectForKey:GPGErrorKey];
    if(anObject == nil)
        anObject = [NSNumber numberWithUnsignedInt:GPGErrorNoError];
    [operationResults setObject:anObject forKey:GPGErrorKey];
    
    if(_operationMask & EncryptOperation){
        gpgme_encrypt_result_t	aResult = gpgme_op_encrypt_result(_context);

        if(aResult != NULL){
            NSDictionary	*aDict = [self _invalidKeysReasons:aResult->invalid_recipients keys:[_operationData objectForKey:@"keys"]];

            if(aDict != nil)
                [operationResults setObject:aDict forKey:@"keyErrors"];
        }

        if(gpgme_err_code([[_operationData objectForKey:GPGErrorKey] unsignedIntValue]) == GPG_ERR_UNUSABLE_PUBKEY){
            [operationResults setObject:[_operationData objectForKey:@"cipher"] forKey:@"cipher"];
        }
    }
    
    if(_operationMask & SignOperation){
        gpgme_sign_result_t	signResult = gpgme_op_sign_result(_context);

        if(gpgme_err_code([[_operationData objectForKey:GPGErrorKey] unsignedIntValue]) == GPG_ERR_UNUSABLE_SECKEY){
            [operationResults setObject:[_operationData objectForKey:@"signedData"] forKey:@"signedData"];
        }
        
        if(signResult != NULL){
            gpgme_new_signature_t	aSignature = signResult->signatures;
            NSMutableArray			*newSignatures = [NSMutableArray array];
            NSDictionary			*aDict;

            while(aSignature != NULL){
                GPGSignature	*newSignature = [[GPGSignature alloc] initWithNewSignature:aSignature];

                [newSignatures addObject:newSignature];
                [newSignature release];
                aSignature = aSignature->next;
            }
            if([newSignatures count] > 0)
                [operationResults setObject:newSignatures forKey:@"newSignatures"];

            aDict = [self _invalidKeysReasons:signResult->invalid_signers keys:[self signerKeys]];

            if(aDict != nil){
                NSDictionary	*oldDict = [operationResults objectForKey:@"keyErrors"];

                if(oldDict == nil)
                    [operationResults setObject:aDict forKey:@"keyErrors"];
                else{
                    // WARNING: we cannot have an error for the same key coming
                    // from encryption and signing. Shouldn't be a problem though.
                    if([[NSSet setWithArray:[oldDict allKeys]] intersectsSet:[NSSet setWithArray:[aDict allKeys]]])
                        NSLog(@"### Does not support having more than one error for the same key; ignoring some errors.");
                    oldDict = [NSMutableDictionary dictionaryWithDictionary:oldDict];
                    [(NSMutableDictionary *)oldDict addEntriesFromDictionary:aDict];
                    [operationResults setObject:oldDict forKey:@"keyErrors"];
                }
            }
        }
    }
    
    if(_operationMask & VerifyOperation){
        gpgme_verify_result_t	aResult = gpgme_op_verify_result(_context);
        
        if(aResult != NULL){
            NSArray	*signatures = [self signatures];
            
            if(signatures != nil)
                [operationResults setObject:signatures forKey:@"signatures"];
            if(aResult->file_name != NULL)
                [operationResults setObject:GPGStringFromChars(aResult->file_name) forKey:@"filename"];
        }
    }
    
    if(_operationMask & DecryptOperation){
        gpgme_decrypt_result_t	aResult = gpgme_op_decrypt_result(_context);

        if(aResult != NULL){
            gpgme_recipient_t   recipients = aResult->recipients;
            NSMutableDictionary *keyErrors = [[NSMutableDictionary alloc] init];
            GPGContext          *aContext = [self copy];
            
            if(aResult->unsupported_algorithm != NULL)
                [operationResults setObject:GPGStringFromChars(aResult->unsupported_algorithm) forKey:@"unsupportedAlgorithm"];
            if(!!aResult->wrong_key_usage)
                [operationResults setObject:[NSNumber numberWithBool:!!aResult->wrong_key_usage] forKey:@"wrongKeyUsage"];
            if(aResult->file_name != NULL)
                [operationResults setObject:GPGStringFromChars(aResult->file_name) forKey:@"filename"];
            
            while(recipients != NULL){
                // Try to get secret then public GPGKey for that keyID.
                // If none, create GPGRemoteKey
                NSString        *aKeyID = [[NSString alloc] initWithFormat:@"%s", recipients->keyid];
                id              aKey;
                
                if(recipients->status == GPGErrorNoError){
                    aKey = [aContext keyFromFingerprint:aKeyID secretKey:YES];
                    NSAssert1(aKey != nil, @"### Unable to find decryption secret key %s?!", recipients->keyid);
                }
                else{
                    aKey = [aContext keyFromFingerprint:aKeyID secretKey:NO];
                    if(aKey == nil)
                        aKey = [[[GPGRemoteKey alloc] initWithRecipient:recipients] autorelease];
                }
                [keyErrors setObject:[NSNumber numberWithUnsignedInt:recipients->status] forKey:aKey];
                recipients = recipients->next;
                [aKeyID release];
            }
            [aContext release];
            [operationResults setObject:keyErrors forKey:@"keyErrors"];
            [keyErrors release];
        }
    }
    
    if(_operationMask & ImportOperation){
        gpgme_import_result_t	result = gpgme_op_import_result(_context);

        if(result != NULL){
            NSMutableDictionary		*keys = [NSMutableDictionary dictionary];
            gpgme_import_status_t	importStatus = result->imports;

            [operationResults setObject:[NSNumber numberWithInt:result->considered] forKey:@"consideredKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->no_user_id] forKey:@"keysWithoutUserIDCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->imported] forKey:@"importedKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->imported_rsa] forKey:@"importedRSAKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->unchanged] forKey:@"unchangedKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->new_user_ids] forKey:@"newUserIDCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->new_sub_keys] forKey:@"newSubkeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->new_signatures] forKey:@"newSignatureCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->new_revocations] forKey:@"newRevocationCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->secret_read] forKey:@"readSecretKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->secret_imported] forKey:@"importedSecretKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->secret_unchanged] forKey:@"unchangedSecretKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->skipped_new_keys] forKey:@"skippedNewKeyCount"];
            [operationResults setObject:[NSNumber numberWithInt:result->not_imported] forKey:@"notImportedKeyCount"];

            while(importStatus != NULL){
                BOOL			isSecret = (importStatus->status & GPGME_IMPORT_SECRET) != 0;
                GPGKey			*aKey = [self _keyWithFpr:importStatus->fpr isSecret:isSecret];
                NSDictionary	*statusDict;

                if(importStatus->result == GPG_ERR_NO_ERROR)
                    statusDict = [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:importStatus->status] forKey:@"status"];
                else
                    statusDict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithUnsignedInt:importStatus->status], @"status", [NSNumber numberWithUnsignedInt:importStatus->result], @"error", nil];
                NSAssert1(aKey != nil, @"### Unable to retrieve key matching fpr %s", importStatus->fpr);
                [keys setObject:statusDict forKey:aKey];
                importStatus = importStatus->next;
            }
            [operationResults setObject:keys forKey:@"keys"];
        }
    }
    
    if(_operationMask & KeyGenerationOperation){
        gpgme_genkey_result_t	result = gpgme_op_genkey_result(_context);
        
        if(result != NULL && result->fpr != NULL){ // fpr is NULL for CMS
            GPGKey			*publicKey, *secretKey;
            NSDictionary	*keyChangesDict;

            secretKey = [self _keyWithFpr:result->fpr isSecret:YES];
            NSAssert1(secretKey != nil, @"### Unable to retrieve key matching fpr %s", result->fpr);
            publicKey = [self _keyWithFpr:result->fpr isSecret:NO];
            NSAssert1(publicKey != nil, @"### Unable to retrieve key matching fpr %s", result->fpr);
            keyChangesDict = [NSDictionary dictionaryWithObjectsAndKeys:[NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:(GPGImportNewKeyMask | GPGImportSecretKeyMask)] forKey:@"status"], secretKey, [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:GPGImportNewKeyMask] forKey:@"status"], publicKey, nil];
            [operationResults setObject:keyChangesDict forKey:GPGChangesKey];
        }
    }

    if(_operationMask & KeyDeletionOperation){
        NSArray *deletedKeyFingerprints = [_operationData objectForKey:@"deletedKeyFingerprints"];
        
        if(deletedKeyFingerprints)
            [operationResults setObject:deletedKeyFingerprints forKey:@"deletedKeyFingerprints"];
    }
    
    if(_operationMask & KeyListingOperation){
        gpgme_keylist_result_t	result = gpgme_op_keylist_result(_context);

        if(result != NULL){
            [operationResults setObject:[NSNumber numberWithBool:!!result->truncated] forKey:@"truncated"];
        }
    }

    if(_operationMask & RemoteKeyListingOperation){
        id	anObject;

        [operationResults setObject:[_operationData objectForKey:@"hostName"] forKey:@"hostName"];
        [operationResults setObject:[_operationData objectForKey:@"protocol"] forKey:@"protocol"];
        [operationResults setObject:[_operationData objectForKey:@"options"] forKey:@"options"];
        anObject = [_operationData objectForKey:@"port"] ;
        if(anObject != nil)
            [operationResults setObject:anObject forKey:@"port"];
        anObject = [_operationData objectForKey:@"keys"] ;
        if(anObject != nil)
            [operationResults setObject:anObject forKey:@"keys"];
    }

    if(_operationMask & KeyDownloadOperation){
        id	anObject;
        
        [operationResults setObject:[_operationData objectForKey:@"hostName"] forKey:@"hostName"];
        [operationResults setObject:[_operationData objectForKey:@"protocol"] forKey:@"protocol"];
        [operationResults setObject:[_operationData objectForKey:@"options"] forKey:@"options"];
        anObject = [_operationData objectForKey:@"port"] ;
        if(anObject != nil)
            [operationResults setObject:anObject forKey:@"port"];
    }
/*
    if(_operationMask & KeyUploadOperation){
#warning Missing implementation
    }
*/
    return operationResults;
}

- (void) setUserInfo:(id)newUserInfo
/*"
 * Sets the userInfo object, containing additional data the target may use
 * in a callback, for example when delegate is asked for passphrase.
 * newUserInfo is simply retained.
"*/
{
    id	oldUserInfo = _userInfo;
    
    if(newUserInfo != nil)
        _userInfo = [newUserInfo retain];
    else
        _userInfo = nil;
    if(oldUserInfo != nil)
        [oldUserInfo release];
}

- (id) userInfo
/*"
 * Returns the userInfo object, containing additional data the target may use
 * in a callback, for example when delegate is asked for passphrase.
"*/
{
    return _userInfo;
}

/* Key-Value Coding compliance */
- (void) setNilValueForKey:(NSString *)key
{
    if([key isEqualToString:@"certificatesInclusion"])
        [self setCertificatesInclusion:NO];
    else if([key isEqualToString:@"usesArmor"])
        [self setUsesArmor:NO];
    else if([key isEqualToString:@"usesTextMode"])
        [self setUsesTextMode:NO];
    else
        [super setNilValueForKey:key];
}

- (void) clearSignatureNotations
/*"
 * Clear all notation data from the context. Subsequent signing operations from
 * this context will not include any notation data.
 *
 * Every context starts with an empty notation data list.
"*/
{
    gpgme_sig_notation_clear(_context);
}

- (void) addSignatureNotationWithName:(NSString *)name value:(id)value flags:(GPGSignatureNotationFlags)flags
/*"
 * Add the human-readable notation data with name and value to the context, 
 * using the flags. 
 *
 * If name is nil, then value should be a policy URL, as a NSString; the 
 * notation data is forced not to be a human-readable notation data.
 *
 * If name is not nil, then value may be a NSString (the notation data is forced
 * to be a human-readable notation data). Else value has to be a NSData, and
 * notation data is forced not to be a human-readable notation data.
 *
 * Subsequent signing operations will include this notation data, as well as any
 * other notation data that was added since the creation of the context or the
 * last -clearSignatureNotations invocation.
 *
 * Can raise a #GPGException for any error that is reported by the crypto engine
 * support routines.
 *
 *#WARNING: Non-human-readable notation data is currently not supported.
"*/
{
    const char      *aCStringName;
    const char      *aCStringValue;
    gpgme_error_t	anError;
    
    NSParameterAssert([value isKindOfClass:[NSString class]]);
    
    aCStringName = (name != nil ? [name UTF8String] : NULL);
    aCStringValue = [value UTF8String];
    anError = gpgme_sig_notation_add(_context, aCStringName, aCStringValue, flags);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSArray *) signatureNotations
/*"
 * Returns the signature notations for this context.
"*/
{
    NSMutableArray          *signatureNotations = [NSMutableArray array];
    gpgme_sig_notation_t    eachNotation = gpgme_sig_notation_get(_context);
    
    while(eachNotation != NULL){
        GPGSignatureNotation    *anObject = [[GPGSignatureNotation alloc] initWithInternalRepresentation:eachNotation];
        
        [signatureNotations addObject:anObject];
        eachNotation = eachNotation->next;
        [anObject release];
    }
    
    return signatureNotations;
}

- (NSArray *) engines
/*"
 * Returns the engines as used by the current context.
"*/
{
    if(_engines == nil){
        gpgme_engine_info_t engineInfo = gpgme_ctx_get_engine_info(_context);
        
        _engines = [[GPGEngine enginesFromEngineInfo:engineInfo context:self] retain];
    }
    
    return _engines;
}

- (GPGEngine *) engine
/*"
 * Convenience method. Returns the engine for the protocol currently used.
"*/
{
    NSEnumerator    *engineEnum = [[self engines] objectEnumerator];
    GPGEngine       *anEngine;
    
    while((anEngine = [engineEnum nextObject]))
        if([anEngine engineProtocol] == [self protocol])
            return anEngine;
    
    return nil;
}

@end


@implementation GPGContext(GPGAsynchronousOperations)

#warning Only one thread at a time can call gpgme_wait => protect usage with mutex!

+ (GPGContext *) waitOnAnyRequest:(BOOL)hang
/*"
 * Waits for any finished request. When hang is YES the method will wait,
 * otherwise it will return immediately when there is no pending finished
 * request.
 *
 * Returns the context of the finished request or nil if hang is NO and no
 * request has finished.
 *
 * Can raise a #GPGException which reflects the termination status of the 
 * operation (in case of error). The exception userInfo dictionary contains
 * the context (under #GPGContextKey key) which terminated with the error.
 * An exception without any context could also be raised.
"*/
{
    gpgme_error_t	anError = GPG_ERR_NO_ERROR;
    gpgme_ctx_t		returnedCtx = gpgme_wait(NULL, &anError, hang);
    GPGContext		*newContext;

    if(anError != GPG_ERR_NO_ERROR){
        // Returns an existing context
        if(returnedCtx != NULL){
            newContext = [[GPGContext alloc] initWithInternalRepresentation:returnedCtx];
            [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:[newContext autorelease] forKey:GPGContextKey]] raise];
        }
        else
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
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
 * Returns YES if there is a finished request for context or NO if hang is NO
 * and no request (for context) has finished.
 *
 * Can raise a #GPGException which reflects the termination status
 * of the operation, in case of error.
"*/
{
    /*
     @code{gpgme_wait} can be used only in conjunction with any context
    that has a pending operation initiated with one of the
    @code{gpgme_op_*_start} functions except @code{gpgme_op_keylist_start}
    and @code{gpgme_op_trustlist_start} (for which you should use the
                                         corresponding @code{gpgme_op_*_next} functions).  If @var{ctx} is
    @code{NULL}, all of such contexts are waited upon and possibly
    returned.  Synchronous operations running in parallel, as well as key
    and trust item list operations, do not affect @code{gpgme_wait}.

    In a multi-threaded environment, only one thread should ever call
    @code{gpgme_wait} at any time, irregardless if @var{ctx} is specified
    or not.  This means that all calls to this function should be fully
    synchronized by locking primitives.
    */
    gpgme_error_t	anError = GPG_ERR_NO_ERROR;
    gpgme_ctx_t		returnedCtx = gpgme_wait(_context, &anError, hang);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    
    if(returnedCtx == _context)
        return YES;
    else
        return (returnedCtx != NULL);
}

- (void) cancel
/*"
 * Attempts to cancel a pending operation in the context. This only works if
 * you use the global event loop or your own event loop.
 *
 * Can raise a #GPGException if the cancellation failed (in this case the
 * state of context is not modified).
"*/
{

    /*
     *
     * If you use the global event loop, you must not call -wait: nor
     * +waitOnAnyRequest: during cancellation. After successful cancellation, you
     * can call +waitOnAnyRequest: or -wait:, and the context will appear as if it
     * had finished with the error code #GPGErrorCancelled.
     *
     * If you use your an external event loop, you must ensure that no I/O
     * callbacks are invoked for this context (for example by halting the event
                                               * loop). On successful cancellation, all registered I/O callbacks for this
     * context will be unregistered, and a GPGME_EVENT_DONE event with the error
     * code #GPGErrorCancelled will be signaled.
     */
    gpgme_error_t	anError = gpgme_cancel(_context);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

@end


@implementation GPGContext(GPGSynchronousOperations)

- (GPGData *) decryptedData:(GPGData *)inputData
/*"
 * Decrypts the ciphertext in the inputData and returns the plain data.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to
 *                             decrypt.}
 * _{GPGErrorDecryptionFailed  inputData is not a valid cipher text.}
 * _{GPGErrorBadPassphrase     The passphrase for the secret key could not be
 *                             retrieved.}
 * _{GPGErrorCancelled         User cancelled operation, e.g. when asked for
 *                             passphrase}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_decrypt(_context, [inputData gpgmeData], outputData);
    [self setOperationMask:DecryptOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*aUserInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];
        
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:aUserInfo] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (NSArray *) verifySignatureData:(GPGData *)signatureData againstData:(GPGData *)inputData
/*"
 * Performs a signature check on the %detached signature given in
 * signatureData (plaintext). Returns an array of #GPGSignature instances, by
 * invoking #{-signatures}.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData  inputData does not contain any data to verify.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_error_t	anError = gpgme_op_verify(_context, [signatureData gpgmeData], [inputData gpgmeData], NULL);

    [self setOperationMask:VerifyOperation | ImportOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*aUserInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];
        
        [[NSException exceptionWithGPGError:anError userInfo:aUserInfo] raise];
    }
    
    return [self signatures];
}

- (NSArray *) verifySignedData:(GPGData *)signedData
/*"
 * Performs a signature check on signedData. This methods invokes
 * #{-verifySignedData:originalData:} with originalData set to NULL.
 * 
 * Can raise a #GPGException:
 * _{GPGErrorNoData  inputData does not contain any data to verify.}
 * Others exceptions could be raised too.
"*/
{
    return [self verifySignedData:signedData originalData:NULL];
}

- (NSArray *) verifySignedData:(GPGData *)signedData originalData:(GPGData **)originalDataPtr
/*"
 * Returns an array of #GPGSignature instances. originalDataPtr will contain
 * (on success) the data that has been signed. It can be NULL.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to verify.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	uninitializedData;
    gpgme_error_t	anError;
    
    anError = gpgme_data_new(&uninitializedData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    anError = gpgme_op_verify(_context, [signedData gpgmeData], NULL, uninitializedData);
    [self setOperationMask:VerifyOperation | ImportOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*aUserInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];

        gpgme_data_release(uninitializedData);
        [[NSException exceptionWithGPGError:anError userInfo:aUserInfo] raise];
    }

    if(originalDataPtr == NULL)
        gpgme_data_release(uninitializedData);
    else
        *originalDataPtr = [[[GPGData alloc] initWithInternalRepresentation:uninitializedData] autorelease];

    return [self signatures];
}

- (NSArray *) signatures
/*"
 * Returns an array of #GPGSignatures after
 * #{-verifySignedData:}, #{-verifySignedData:originalData:},
 * #{-verifySignatureData:againstData:} or
 * #{-decryptedData:signatureStatus:} has been called. A single detached
 * signature can contain signatures by more than one key. Returns nil if
 * operation was not a verification.
 *
 * After #{-decryptedData:signatureStatus:}, a GPGException with error code
 * GPGErrorNoData counts as successful in this context.
"*/
{
    gpgme_verify_result_t	aResult;
    NSMutableArray			*signatures;
    gpgme_signature_t		aSignature;

    aResult = gpgme_op_verify_result(_context);
    if(aResult == NULL)
        return nil;
    
    signatures = [NSMutableArray array];
    aSignature = aResult->signatures;
    while(aSignature != NULL){
        GPGSignature	*newSignature = [[GPGSignature alloc] initWithSignature:aSignature];

        [signatures addObject:newSignature];
        [newSignature release];
        aSignature = aSignature->next;
    }

    return signatures;
}

- (GPGData *) decryptedData:(GPGData *)inputData signatures:(NSArray **)signaturesPtr
/*"
 * Decrypts the ciphertext in inputData and returns it as plain. If cipher
 * contains signatures, they will be verified and returned in *signaturesPtr,
 * if signaturesPtr is not NULL, by invoking #{-signatures}.
 *
 * With OpenPGP engine, user has 3 attempts for passphrase in case of public
 * key encryption, else only 1 attempt.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData            inputData does not contain any data to
 *                             decrypt. However, it might still be signed. The
 *                             information about detected signatures is
 *                             available with #{-signatures} in this case.}
 * _{GPGErrorDecryptionFailed  inputData is not a valid cipher text.}
 * _{GPGErrorBadPassphrase     The passphrase for the secret key could not be
 *                             retrieved.}
 * _{GPGErrorCancelled         User cancelled operation, e.g. when asked for
 *                             passphrase}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;

    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    anError = gpgme_op_decrypt_verify(_context, [inputData gpgmeData], outputData);
    [self setOperationMask:DecryptOperation | VerifyOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*aUserInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];

        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:aUserInfo] raise];
    }

    if(signaturesPtr != NULL)
        *signaturesPtr = [self signatures];

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGKey *) _keyWithFpr:(const char *)fpr fromKeys:(NSArray *)keys
{
    // fpr can be either a fingerprint OR a keyID
    NSString		*aFingerprint = GPGStringFromChars(fpr);
    NSEnumerator	*anEnum = [keys objectEnumerator];
    GPGKey			*aKey;

    while(aKey = [anEnum nextObject])
        // Maybe we'd better compare keyID to key's ID/fingerprint or one of its _subkeys_ ID
        if([[aKey fingerprint] isEqualToString:aFingerprint] || [[aKey keyID] isEqualToString:aFingerprint])
            return aKey;

    [NSException raise:NSInternalInconsistencyException format:@"### Unable to find key matching %s among %@", fpr, keys];

    return nil;
}

- (NSDictionary *) _invalidKeysReasons:(gpgme_invalid_key_t)invalidKeys keys:(NSArray *)keys
{
    if(invalidKeys != NULL){
        NSMutableDictionary	*keyErrors = [NSMutableDictionary dictionary];

        // WARNING: Does not support having more than one problem per key!
        // This could theoretically happen, but does not currently
        while(invalidKeys != NULL){
            GPGKey	*aKey = [self _keyWithFpr:invalidKeys->fpr fromKeys:keys]; // fpr or keyID!

            if([keyErrors objectForKey:aKey] != nil)
                NSLog(@"### Does not support having more than one error per key. Ignoring error %u (%@) for key %@", invalidKeys->reason, GPGErrorDescription(invalidKeys->reason), aKey);
            else
                [keyErrors setObject:[NSNumber numberWithUnsignedInt:invalidKeys->reason] forKey:aKey];
            invalidKeys = invalidKeys->next;
        }
        if([keyErrors count] > 0)
            return keyErrors;
    }
    return nil;
}

- (GPGData *) signedData:(GPGData *)inputData signatureMode:(GPGSignatureMode)mode
/*"
 * Creates a signature for the text in inputData and returns either the signed
 * data or a detached signature, depending on the mode. Data will be signed
 * using either the default key (defined in engine configuration file) or the
 * ones defined in context. The type of the signature created is determined by
 * the ASCII armor and text mode attributes set for the context and the
 * requested signature mode mode.
 *
 * A signature can contain signatures by one or more keys. The set of keys
 * used to create a signatures is contained in the context, and is applied to
 * all following signing operations in the context (until the set is changed).
 *
 * If an S/MIME signed message is created using the CMS crypto engine, the
 * number of certificates to include in the message can be specified with
 * #{-setIncludedCertificates:}.
 * 
 * Note that settings done by #{-setUsesArmor:} and #{-setUsesTextMode:} are
 * ignored for mode #GPGSignatureModeClear.
 *
 * With OpenPGP engine, user has 3 attempts for passphrase.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData             The signature could not be created.}
 * _{GPGErrorBadPassphrase      The passphrase for the secret key could not be
 *                              retrieved.}
 * _{GPGErrorUnusableSecretKey  There are invalid signers.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;
    GPGData			*signedData;

    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    signedData = [[GPGData alloc] initWithInternalRepresentation:outputData];

    anError = gpgme_op_sign(_context, [inputData gpgmeData], outputData, mode);
    [self setOperationMask:SignOperation];
    [_operationData setObject:signedData forKey:@"signedData"];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*userInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];
        
        [signedData release];
        [[NSException exceptionWithGPGError:anError userInfo:userInfo] raise];
    }

    return [signedData autorelease];
}

- (NSArray *) _flattenedKeys:(NSArray *)keysAndKeyGroups
{
    int             itemCount = [keysAndKeyGroups count];
    NSMutableArray  *keys = [NSMutableArray arrayWithCapacity:itemCount];
    int             i;
    
    for(i = 0; i < itemCount; i++){
        id  aKeyOrGroup = [keysAndKeyGroups objectAtIndex:i];
        
        if([aKeyOrGroup isKindOfClass:[GPGKeyGroup class]])
            [keys addObjectsFromArray:[aKeyOrGroup keys]];
        else
            [keys addObject:aKeyOrGroup];
    }
    
    return keys;
}

- (GPGData *) encryptedData:(GPGData *)inputData withKeys:(NSArray *)keys trustAllKeys:(BOOL)trustAllKeys
/*"
 * Encrypts the plaintext in inputData with the keys and returns the 
 * ciphertext. The type of the ciphertext created is determined by the
 * %{ASCII armor} and %{text mode} attributes set for the context.
 *
 * The keys parameters may not be nil, nor be an empty array. It can contain
 * GPGKey instances and GPGKeyGroup instances; you can mix them.
 *
 * If the trustAllKeys parameter is set to YES, then all passed keys will be
 * trusted, even if the keys do not have a high enough validity in the
 * key-ring. This flag should be used with care; in general it is not a good
 * idea to use any untrusted keys.
 *
 * Can raise a #GPGException:
 * _{GPGErrorUnusablePublicKey  Some recipients in keys are invalid, but not
 *                              all. In this case the plaintext might be
 *                              encrypted for all valid recipients and
 *                              returned in #{-operationResults}, for key
 *                              #{@"cipher"} (if this happens depends on the
 *                              crypto engine). More information about the
 *                              invalid recipients is available in
 *                              #{-operationResults}, under key
 *                              #{@"keyErrors"} which has a dictionary as
 *                              value; that dictionary uses GPGKey instances
 *                              as keys, and GPGError NSNumber instances as
 *                              values.}
 * _{GPGErrorGeneralError       For example, some keys were not trusted. See
 *                              #{-operationResults}, under key
 *                              #{@"keyErrors"}.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;
    gpgme_key_t		*encryptionKeys;
    int				i = 0, keyCount;
    GPGData			*cipher;

    NSParameterAssert(keys != nil); // Would mean symmetric encryption
    
    keys = [self _flattenedKeys:keys];
    keyCount = [keys count];
    NSAssert(keyCount > 0, @"### No keys or group(s) expand to no keys!"); // Would mean symmetric encryption

    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    cipher = [[GPGData alloc] initWithInternalRepresentation:outputData];
    
    encryptionKeys = NSZoneMalloc(NSDefaultMallocZone(), sizeof(gpgme_key_t) * (keyCount + 1));
    for(i = 0; i < keyCount; i++)
        encryptionKeys[i] = [[keys objectAtIndex:i] gpgmeKey];
    encryptionKeys[i] = NULL;

    anError = gpgme_op_encrypt(_context, encryptionKeys, (trustAllKeys ? GPGME_ENCRYPT_ALWAYS_TRUST:0), [inputData gpgmeData], outputData);
    [self setOperationMask:EncryptOperation];
    NSZoneFree(NSDefaultMallocZone(), encryptionKeys);

    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    [_operationData setObject:cipher forKey:@"cipher"];

    if(anError != GPG_ERR_NO_ERROR){
        [_operationData setObject:keys forKey:@"keys"];
        [cipher release];
        
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]] raise];
    }

    return [cipher autorelease];
}

- (GPGData *) encryptedData:(GPGData *)inputData
/*"
 * Encrypts the plaintext in inputData using symmetric encryption (rather than
 * public key encryption) and returns the ciphertext. The type of the
 * ciphertext created is determined by the %{ASCII armor} and %{text mode}
 * attributes set for the context.
 *
 * Symmetrically encrypted cipher text can be deciphered with
 * #{-decryptedData:}. Note that in this case the crypto backend needs to
 * retrieve a passphrase from the user. Symmetric encryption is currently only
 * supported for the OpenPGP crypto backend.
 *
 * With OpenPGP engine, only one attempt for passphrase is allowed.
 *
 * Can raise a #GPGException:
 * _{GPGErrorBadPassphrase  The passphrase for the symmetric key could not be
 *                          retrieved.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;
    GPGData			*cipher;

    NSAssert([self passphraseDelegate] != nil, @"### No passphrase delegate set for symmetric encryption"); // This is to workaround a bug in gpgme 1.0.2 which doesn't return an error in that case!
    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    cipher = [[GPGData alloc] initWithInternalRepresentation:outputData];

    anError = gpgme_op_encrypt(_context, NULL, 0, [inputData gpgmeData], outputData);
    [self setOperationMask:EncryptOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    [_operationData setObject:cipher forKey:@"cipher"];
    if(anError != GPG_ERR_NO_ERROR){
        [cipher release];
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]] raise];
    }

    return [cipher autorelease];
}

- (GPGData *) encryptedSignedData:(GPGData *)inputData withKeys:(NSArray *)keys trustAllKeys:(BOOL)trustAllKeys
/*"
 * Signs then encrypts, in one operation, the plaintext in inputData for the
 * recipients and returns the ciphertext. The type of the ciphertext created
 * is determined by the %{ASCII armor} and %{text mode} attributes set for the
 * context. The signers are set using #{-addSignerKey:}.
 *
 * This combined encrypt and sign operation is currently only available
 * for the OpenPGP crypto engine.
 *
 * The keys can contain GPGKey instances and GPGKeyGroup instances; you can mix
 * them.
 *
 * Can raise a #GPGException:
 * _{GPGErrorBadPassphrase      The passphrase for the secret key could not be
 *                              retrieved.}
 * _{GPGErrorUnusablePublicKey  Some recipients in keys are invalid, but not
 *                              all. In this case the plaintext might be
 *                              encrypted for all valid recipients and
 *                              returned in #{-operationResults}, under
 *                              key #{@"cipher"} (if this happens depends on
 *                              the crypto engine). More information about the
 *                              invalid recipients is available in
 *                              #{-operationResults}, under key
 *                              #{@"keyErrors"} which has a dictionary as
 *                              value; that dictionary uses GPGKey instances
 *                              as keys, and GPGError NSNumber instances as
 *                              values.}
 * _{GPGErrorUnusableSecretKey  There are invalid signers.}
 * _{GPGErrorGeneralError       For example, some keys were not trusted. See
 *                              #{-operationResults}, under key
 *                              #{@"keyErrors"}.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;
    gpgme_key_t		*encryptionKeys;
    int				i = 0, keyCount = [keys count];
    GPGData			*cipher;

    NSParameterAssert(keys != nil); // Would mean symmetric encryption
    
    keys = [self _flattenedKeys:keys];
    keyCount = [keys count];
    NSAssert(keyCount > 0, @"### No keys or group(s) expand to no keys!"); // Would mean symmetric encryption
    
    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    cipher = [[GPGData alloc] initWithInternalRepresentation:outputData];

    encryptionKeys = NSZoneMalloc(NSDefaultMallocZone(), sizeof(gpgme_key_t) * (keyCount + 1));
    for(i = 0; i < keyCount; i++)
        encryptionKeys[i] = [[keys objectAtIndex:i] gpgmeKey];
    encryptionKeys[i] = NULL;

    anError = gpgme_op_encrypt_sign(_context, encryptionKeys, (trustAllKeys ? GPGME_ENCRYPT_ALWAYS_TRUST:0), [inputData gpgmeData], outputData);
    [self setOperationMask:EncryptOperation | SignOperation];
    NSZoneFree(NSDefaultMallocZone(), encryptionKeys);
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    [_operationData setObject:cipher forKey:@"cipher"];

    if(anError != GPG_ERR_NO_ERROR){
        NSDictionary	*userInfo;

        [_operationData setObject:keys forKey:@"keys"];
        userInfo = [NSDictionary dictionaryWithObject:self forKey:GPGContextKey];

        [cipher release];
        [[NSException exceptionWithGPGError:anError userInfo:userInfo] raise];
    }

    return [cipher autorelease];
}

- (GPGData *) exportedKeys:(NSArray *)keys
/*"
 * Extracts the public key data from keys and returns them. The type of the
 * public keys returned is determined by the %{ASCII armor} attribute set for
 * the context, by invoking #{-setUsesArmor:}.
 *
 * If keys is nil, then all available keys are exported.
 * 
 * Keys are exported from standard key-ring.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_data_t	outputData;
    gpgme_error_t	anError;
    const char		**patterns;

    anError = gpgme_data_new(&outputData);
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    if(keys != nil){
        int	patternCount = [keys count];
        int	i;
        
        patterns = NSZoneMalloc(NSDefaultMallocZone(), (patternCount + 1) * sizeof(char *));
        for(i = 0; i < patternCount; i++)
            patterns[i] = [[[keys objectAtIndex:i] fingerprint] UTF8String];
        patterns[i] = NULL;
    }
    else
        patterns = NULL;
    
    anError = gpgme_op_export_ext(_context, patterns, 0, outputData);
    [self setOperationMask:ExportOperation];
    NSZoneFree(NSDefaultMallocZone(), patterns);
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];

    if(anError != GPG_ERR_NO_ERROR){
        gpgme_data_release(outputData);
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    return [[[GPGData alloc] initWithInternalRepresentation:outputData] autorelease];
}

- (GPGKey *) _keyWithFpr:(const char *)fpr isSecret:(BOOL)isSecret
{
    // WARNING: we need to call this method in a context other than self,
    // because we start a new operation, thus rendering current operation results
    // invalid.
    GPGContext	*localContext = [self copy];
    GPGKey      *aKey = nil;
    
    NS_DURING
        aKey = [localContext keyFromFingerprint:[NSString stringWithUTF8String:fpr] secretKey:isSecret];
    NS_HANDLER
        [localContext release];
        [localException raise];
    NS_ENDHANDLER
    
    [localContext release];
    
    return aKey;
}

- (NSDictionary *) convertedChangesDictionaryForDistributedNotification:(NSDictionary *)dictionary
{
    // We replace all GPGKey instances (which are the keys in the dictionary)
    // by key fingerprints as NSString instances
    NSMutableDictionary *convertedDictionary = [NSMutableDictionary dictionaryWithCapacity:[dictionary count]];
    NSEnumerator        *keyEnum = [dictionary keyEnumerator];
    GPGKey              *aKey;
    
    while((aKey = [keyEnum nextObject]))
        // FIXME No difference between secret and public keys
        [convertedDictionary setObject:[dictionary objectForKey:aKey] forKey:[aKey fingerprint]];
    
    return convertedDictionary;
}


- (NSDictionary *) importKeyData:(GPGData *)keyData
/*"
 * Adds the keys in keyData to the key-ring of the crypto engine used by the
 * context. The format of keyData content can be %{ASCII armored}, for
 * example, but the details are specific to the crypto engine.
 *
 * See #{-operationResults} for information about returned dictionary.
 *
 * If key-ring changed, a #GPGKeyringChangedNotification notification is
 * posted.
 *
 * Can raise a #GPGException:
 * _{GPGErrorNoData  keydata is an empty buffer.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_error_t			anError = gpgme_op_import(_context, [keyData gpgmeData]);
    gpgme_import_result_t	result;
    NSMutableDictionary		*changedKeys;
    gpgme_import_status_t	importStatus;

    [self setOperationMask:ImportOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:self forKey:GPGContextKey]] raise];

    changedKeys = [NSMutableDictionary dictionary];
    result = gpgme_op_import_result(_context);
    importStatus = result->imports;
    while(importStatus != NULL){
        if(importStatus->status != 0){
            BOOL			isSecret = (importStatus->status & GPGME_IMPORT_SECRET) != 0;
            GPGKey			*aKey = [self _keyWithFpr:importStatus->fpr isSecret:isSecret];
            NSDictionary	*statusDict;

            NSAssert1(aKey != nil, @"### Unable to retrieve key matching fpr %s", importStatus->fpr);
            if(importStatus->result == GPG_ERR_NO_ERROR)
                statusDict = [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:importStatus->status] forKey:@"status"];
            else
                statusDict = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithUnsignedInt:importStatus->status], @"status", [NSNumber numberWithUnsignedInt:importStatus->result], @"error", nil];
            
            [changedKeys setObject:statusDict forKey:aKey];
        }
        importStatus = importStatus->next;
    }

    // Posts notif only if key-ring changed
    if([changedKeys count] > 0){
        [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObjectsAndKeys:self, GPGContextKey, changedKeys, GPGChangesKey, nil]];
        [[NSDistributedNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObjectsAndKeys:[self convertedChangesDictionaryForDistributedNotification:changedKeys], GPGChangesKey, nil]];
    }

    return [self operationResults];
}

- (NSString *) xmlStringForString:(NSString *)string
{
    int				i;
    NSMutableString	*xmlString = [NSMutableString stringWithString:string];
    
    for(i = [string length] - 1; i >= 0; i--){
        unichar	aChar = [string characterAtIndex:i];

        switch(aChar){
            case '\n':
                [xmlString replaceCharactersInRange:NSMakeRange(i, 1) withString:@" "]; break;
            case '<':
                [xmlString replaceCharactersInRange:NSMakeRange(i, 1) withString:@"&lt;"]; break;
            case '>':
                [xmlString replaceCharactersInRange:NSMakeRange(i, 1) withString:@"&gt;"]; break;
            case ':':
                [xmlString replaceCharactersInRange:NSMakeRange(i, 1) withString:@"\\x3a"]; break;
            case '&':
                [xmlString replaceCharactersInRange:NSMakeRange(i, 1) withString:@"&amp;"];
        }
    }
    
    return xmlString;
}

- (NSDictionary *) generateKeyFromDictionary:(NSDictionary *)params secretKey:(GPGData *)secretKeyData publicKey:(GPGData *)publicKeyData
/*"
 * Generates a new key pair and puts it into the standard key-ring if both
 * publicKeyData and secretKeyData are nil. In this case method returns
 * immediately after starting the operation, and does not wait for it to
 * complete. If publicKeyData is not nil, the newly created data object, upon
 * successful completion, will contain the public key. If secretKeyData is not
 * nil, the newly created data object, upon successful completion, will
 * contain the secret key.
 *
 * Note that not all crypto engines support this interface equally.
 *
 * GnuPG does not support publicKeyData and secretKeyData, they should be both
 * nil. GnuPG will generate a key pair and add it to the standard key-ring.
 *
 * GpgSM requires publicKeyData to be a writable data object. GpgSM will
 * generate a secret key (which will be stored by gpg-agent), and return a
 * certificate request in public, which then needs to be signed by the
 * certification authority and imported before it can be used.
 *
 * The params dictionary specifies parameters for the key. The details about
 * the format of params are specific to the crypto engine used by the context.
 * Here's an example for #GnuPG as the crypto engine:
 * _{@"type"            algorithm number or name}
 * _{@"length"  Key     NSlength in bits as a NSNumber}
 * _{@"subkeyType"      NSString (ELG-E, etc.) or NSNumber. Optional.}
 * _{@"subkeyLength"    Subkey length in bits as a NSNumber. Optional.}
 * _{@"name"            NSString. Optional.}
 * _{@"comment"         NSString. Optional.}
 * _{@"email"           NSString. Optional.}
 * _{@"expirationDate"  NSCalendarDate. Optional.}
 * _{@"passphrase"      NSString. Optional.}
 * Here's an example for #GpgSM as the crypto engine:
 * _{@"type"    NSString (RSA, etc.) or NSNumber}
 * _{@"length"  Key length in bits as a NSNumber}
 * _{@"name"    NSString (C=de,O=g10 code,OU=Testlab,CN=Joe 2 Tester)}
 * _{@"email"   NSString (joe@foo.bar)}
 * Key is generated in standard secring/pubring files if both secretKeyData
 * and publicKeyData are nil, else newly created key is returned but not 
 * stored.
 *
 * See #{-operationResults} for more information about returned dictionary.
 *
 * A #GPGKeyringChangedNotification notification is posted, containg the new
 * GPGKey instances (secret and public, for OpenPGP only).
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidValue  params is not a valid XML string.}
 * _{GPGErrorNotSupported  publicKeyData or secretKeyData is not nil.}
 * _{GPGErrorGeneralError  No key was created by the engine.}
 * Others exceptions could be raised too.
"*/
{
    NSMutableString	*xmlString = [[NSMutableString alloc] init];
    id				aValue;
    gpgme_error_t	anError;
    NSDictionary	*keyChangesDict;
    NSDictionary	*operationResults;
    
    [xmlString appendString:@"<GnupgKeyParms format=\"internal\">\n"];
    [xmlString appendFormat:@"Key-Type: %@\n", [params objectForKey:@"type"]]; // number or string
    [xmlString appendFormat:@"Key-Length: %@\n", [params objectForKey:@"length"]]; // number or string
    aValue = [params objectForKey:@"subkeyType"]; // number or string; optional
    if(aValue != nil){
        [xmlString appendFormat:@"Subkey-Type: %@\n", aValue];
        [xmlString appendFormat:@"Subkey-Length: %@\n", [params objectForKey:@"subkeyLength"]]; // number or string
    }
    aValue = [params objectForKey:@"name"];
    if(aValue != nil){
        if([self protocol] == GPGOpenPGPProtocol)
            [xmlString appendFormat:@"Name-Real: %@\n", [self xmlStringForString:aValue]];
        else
            [xmlString appendFormat:@"Name-DN: %@\n", [self xmlStringForString:aValue]];
    }
    aValue = [params objectForKey:@"comment"];
    if(aValue != nil)
        [xmlString appendFormat:@"Name-Comment: %@\n", [self xmlStringForString:aValue]];
    aValue = [params objectForKey:@"email"];
    if(aValue != nil)
        [xmlString appendFormat:@"Name-Email: %@\n", [self xmlStringForString:aValue]];
    aValue = [params objectForKey:@"expirationDate"];
    if(aValue != nil)
        [xmlString appendFormat:@"Expire-Date: %@\n", [aValue descriptionWithCalendarFormat:@"%Y-%m-%d"]];
    else
        [xmlString appendString:@"Expire-Date: 0\n"];
    aValue = [params objectForKey:@"passphrase"];
    if(aValue != nil)
        [xmlString appendFormat:@"Passphrase: %@\n", [self xmlStringForString:aValue]];
    [xmlString appendString:@"</GnupgKeyParms>\n"];
    
    anError = gpgme_op_genkey(_context, [xmlString UTF8String], [publicKeyData gpgmeData], [secretKeyData gpgmeData]);
    [self setOperationMask:KeyGenerationOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:[xmlString autorelease] forKey:@"XML"]] raise];
    [xmlString release];

    operationResults = [self operationResults];
    keyChangesDict = [operationResults objectForKey:GPGChangesKey];
    
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObjectsAndKeys:self, GPGContextKey, keyChangesDict, GPGChangesKey, nil]];
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObjectsAndKeys:[self convertedChangesDictionaryForDistributedNotification:keyChangesDict], GPGChangesKey, nil]];

    return keyChangesDict;
}

- (void) deleteKey:(GPGKey *)key evenIfSecretKey:(BOOL)allowSecret
/*"
 * Deletes the given key from the standard key-ring of the crypto engine used
 * by the context. To delete a secret key along with the public key,
 * allowSecret must be YES, else only the public key is deleted, if that is
 * supported.
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidKey  key could not be found in the key-ring.}
 * _{GPGErrorConflict    Secret key for key is available, but allowSecret is
 *                       NO.}
"*/
{
    gpgme_error_t	anError;
    NSString        *aFingerprint;
    NSArray         *deletedKeyFingerprints;

    NSParameterAssert(key != nil);
    aFingerprint = [[key fingerprint] retain];
    anError = gpgme_op_delete(_context, [key gpgmeKey], allowSecret);
    [self setOperationMask:KeyDeletionOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    deletedKeyFingerprints = [NSArray arrayWithObject:aFingerprint];
    [_operationData setObject:deletedKeyFingerprints forKey:@"deletedKeyFingerprints"];
#warning TODO
    // We should mark GPGKey as deleted, and it would raise an exception on any method invocation
    [[NSNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObjectsAndKeys:self, GPGContextKey, deletedKeyFingerprints, @"deletedKeyFingerprints", nil]];
    [[NSDistributedNotificationCenter defaultCenter] postNotificationName:GPGKeyringChangedNotification object:nil userInfo:[NSDictionary dictionaryWithObject:[NSDictionary dictionaryWithObject:[NSNumber numberWithInt:GPGImportDeletedKeyMask] forKey:aFingerprint] forKey:GPGChangesKey]]; // FIXME No difference between secret and public keys
    [aFingerprint release];
}

- (GPGKey *) keyFromFingerprint:(NSString *)fingerprint secretKey:(BOOL)secretKey
/*"
 * Fetches a single key, given its fingerprint (or key ID). If secretKey is
 * YES, returns a secret key, else returns a public key. You can set the key
 * list mode if you want to retrieve key signatures too. Returns nil if no
 * matching key is found.
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidKey     fingerprint is not a valid fingerprint, nor key
 *                          ID.}
 * _{GPGErrorAmbiguousName  the key ID was not a unique specifier for a key.}
 * _{GPGErrorBusy           Context (self) is already performing an operation.}
 * Others exceptions could be raised too.
"*/
{
    gpgme_error_t	anError;
    gpgme_key_t		aKey = NULL;

    NSParameterAssert(fingerprint != nil);
    anError = gpgme_get_key(_context, [fingerprint UTF8String], &aKey, secretKey);
    [self setOperationMask:SingleKeyListingOperation];
    [_operationData setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
    if(anError != GPG_ERR_NO_ERROR){
        if(gpgme_err_code(anError) == GPG_ERR_EOF)
            aKey = NULL;
        else
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    if(aKey != NULL)
        return [[[GPGKey alloc] initWithInternalRepresentation:aKey] autorelease];
    else
        return nil;
}

- (GPGKey *) refreshKey:(GPGKey *)key
/*"
 * Asks the engine for the key again, forcing a refresh of the key attributes.
 * This method can be used to fetch key signatures, by setting corresponding
 * mode in the context. A new #GPGKey instance is returned; you shall no
 * longer use the original key.
 *
 * Invokes #{-keyFromFingerprint:secretKey:}
 *
 * Can raise a #GPGException:
 * _{GPGErrorBusy  Context (self) is already performing an operation.}
 * Others exceptions could be raised too.
"*/
{
    NSString	*aString;
    
    NSParameterAssert(key != nil);

    aString = [key fingerprint];
    if(aString == nil)
        aString = [key keyID];
    
    return [self keyFromFingerprint:aString secretKey:[key isSecret]];
}

@end


@implementation GPGContext(GPGKeyManagement)

- (NSEnumerator *) keyEnumeratorForSearchPattern:(NSString *)searchPattern secretKeysOnly:(BOOL)secretKeysOnly
/*"
 * Convenience method. Passing nil will return all keys. See
 * #{-keyEnumeratorForSearchPatterns:secretKeysOnly:}.
"*/
{
    return [[[GPGKeyEnumerator alloc] initForContext:self searchPattern:searchPattern secretKeysOnly:secretKeysOnly] autorelease];
}

- (NSEnumerator *) keyEnumeratorForSearchPatterns:(NSArray *)searchPatterns secretKeysOnly:(BOOL)secretKeysOnly
/*"
 * Returns an enumerator of #GPGKey instances. It starts a key listing
 * operation inside the context; the context will be busy until either all
 * keys are received, or #{-stopKeyEnumeration} is invoked, or the enumerator
 * has been deallocated.
 *
 * searchPatterns is an array containing engine specific expressions that are
 * used to limit the list to all keys matching at least one pattern.
 * searchPatterns can be empty; in this case all keys are returned. Note that
 * the total length of the pattern string (i.e. the length of all patterns, 
 * sometimes quoted, separated by a space character) is restricted to an 
 * engine-specific maximum (a couple of hundred characters are usually 
 * accepted). The patterns should be used to restrict the search to a certain 
 * common name or user, not to list many specific keys at once by listing their
 * fingerprints or key IDs.
 *
 * If secretKeysOnly is YES, searches only for secret keys.
 *
 * This call also resets any pending key listing operation.
 *
 * Can raise a #GPGException, even during enumeration. Raises an exception
 * with code #GPGErrorTruncatedKeyListing during enumeration (i.e. when
 * when invoking -nextObject on the enumerator) if the crypto backend had to
 * truncate the result, and less than the desired keys could be listed.
 *
 * #WARNING: there is a bug in gpg: secret keys fetched in batch (i.e. with this
 * method) have no capabilities and you need to invoke -refreshKey: on each to  
 * get full information for them.
"*/
{
    return [[[GPGKeyEnumerator alloc] initForContext:self searchPatterns:searchPatterns secretKeysOnly:secretKeysOnly] autorelease];
}

- (void) stopKeyEnumeration
/*"
 * Ends the key listing operation and allows to use the context for some
 * other operation next. This is not an error to invoke that method if there
 * is no pending key listing operation.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_error_t	anError = gpgme_op_keylist_end(_context);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSEnumerator *) trustItemEnumeratorForSearchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
/*"
 * Returns an enumerator of #GPGTrustItem instances, and initiates a trust
 * item listing operation inside the context.
 * 
 * searchPattern contains an engine specific expression that is used to limit
 * the list to all trust items matching the pattern. It can not be the empty
 * string or nil.
 *
 * maxLevel is currently ignored.
 *
 * Context will be busy until either all trust items are enumerated, or
 * #{-stopTrustItemEnumeration} is invoked, or the enumerator has been
 * deallocated.
 * 
 * Can raise a #GPGException, even during enumeration.
"*/
{
    return [[[GPGTrustItemEnumerator alloc] initForContext:self searchPattern:searchPattern maximumLevel:maxLevel] autorelease];
}

- (void) stopTrustItemEnumeration
/*"
 * Ends the trust item listing operation and allows to use the context for 
 * some other operation next. This is not an error to invoke that method if
 * there is no pending trust list operation.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_error_t	anError = gpgme_op_trustlist_end(_context);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

@end


@interface GPGOptions(GPGContext_Revealed)
- (NSArray *) _subOptionsForName:(NSString *)optionName;
@end


enum {
    _GPGContextHelperSearchCommand,
    _GPGContextHelperGetCommand,
    _GPGContextHelperUploadCommand
};

@interface _GPGContextHelper : NSObject
{
    GPGContext      *context;
    NSTask          *task;
    NSPipe          *outputPipe;
    NSPipe          *errorPipe;
    id              argument;
    NSString        *hostName;
    NSString        *hostPort;
    NSString        *protocolName;
    NSArray         *serverOptions;
    NSDictionary	*passedOptions;
    BOOL            importOutputData;
    int             command;
    NSMutableArray  *resultKeys;
    BOOL			interrupted;
    int				version;
}

+ (void) helpContext:(GPGContext *)theContext searchingForKeysMatchingPatterns:(NSArray *)theSearchPatterns serverOptions:(NSDictionary *)options;
+ (void) helpContext:(GPGContext *)theContext downloadingKeys:(NSArray *)theKeys serverOptions:(NSDictionary *)options;
+ (void) helpContext:(GPGContext *)theContext uploadingKeys:(NSArray *)theKeys serverOptions:(NSDictionary *)options;
- (void) interrupt;

@end

@implementation _GPGContextHelper

+ (void) performCommand:(int)theCommand forContext:(GPGContext *)theContext argument:(id)theArgument serverOptions:(NSDictionary *)thePassedOptions needsLocking:(BOOL)needsLocking
{
	static NSMutableDictionary	*executableVersions = nil;
	
    _GPGContextHelper	*helper;
    NSTask				*aTask = nil;
    NSMutableString		*commandString = nil;
    NSString			*aHostName;
    NSString			*port = nil;
    NSString			*aString;
    NSString			*aProtocol = nil;
    GPGOptions			*gpgOptions;
    NSRange				aRange;
    NSPipe				*inputPipe, *anOutputPipe, *anErrorPipe;
    NSString			*launchPath = nil;
    NSArray 			*options;
    NSEnumerator		*anEnum;
    int					formatVersion = 0;
    NSNumber			*formatVersionNumber = nil;

	if(executableVersions == nil)
		executableVersions = [[NSMutableDictionary alloc] initWithCapacity:5];
	
    gpgOptions = [[GPGOptions alloc] init];
    aHostName = [thePassedOptions objectForKey:@"keyserver"];
    if(aHostName == nil){
        NSArray	*optionValues = [gpgOptions activeOptionValuesForName:@"keyserver"];

        if([optionValues count] == 0){
            [gpgOptions release];
            [[NSException exceptionWithGPGError:gpgme_error(GPGErrorKeyServerError) userInfo:[NSDictionary dictionaryWithObject:@"No keyserver set" forKey:GPGAdditionalReasonKey]] raise];
        }
        else
            aHostName = [optionValues objectAtIndex:0];
    }

    aRange = [aHostName rangeOfString:@"://"];
    if(aRange.length <= 0){
        aHostName = [@"x-hkp://" stringByAppendingString:aHostName];
        aRange = [aHostName rangeOfString:@"://"];
    }
    aString = [aHostName lowercaseString];
    if([aString hasPrefix:@"ldap://"]){
        launchPath = @"gpgkeys_ldap"; // Hardcoded
        aProtocol = @"ldap";
    }
    else if([aString hasPrefix:@"x-hkp://"]){
        launchPath = @"gpgkeys_hkp"; // Hardcoded
        aProtocol = @"x-hkp";
    }
    else if([aString hasPrefix:@"hkp://"]){
        launchPath = @"gpgkeys_hkp"; // Hardcoded
        aProtocol = @"hkp";
    }
    else if([aString hasPrefix:@"http://"]){
        launchPath = @"gpgkeys_curl"; // Hardcoded
        aProtocol = @"http";
    }
    else if([aString hasPrefix:@"https://"]){
        launchPath = @"gpgkeys_curl"; // Hardcoded
        aProtocol = @"https";
    }
    else if([aString hasPrefix:@"ftp://"]){
        launchPath = @"gpgkeys_curl"; // Hardcoded
        aProtocol = @"ftp";
    }
    else if([aString hasPrefix:@"ftps://"]){
        launchPath = @"gpgkeys_curl"; // Hardcoded
        aProtocol = @"ftps";
    }
    else if([aString hasPrefix:@"finger://"]){
#warning FIXME Not sure that finger URLs start with finger:// 
        launchPath = @"gpgkeys_finger"; // Hardcoded
        aProtocol = @"finger";
    }
    else{
        [gpgOptions release];
        [[NSException exceptionWithGPGError:gpgme_error(GPGErrorKeyServerError) userInfo:[NSDictionary dictionaryWithObject:@"Unsupported keyserver type" forKey:GPGAdditionalReasonKey]] raise];
    }
    aHostName = [aHostName substringFromIndex:aRange.location + 3]; // 3 = length of '://'

#warning FIXME No longer hardcode path
    aString = [@"/usr/local/libexec/gnupg/" stringByAppendingPathComponent:launchPath]; // Hardcoded
    if(![[NSFileManager defaultManager] fileExistsAtPath:aString]){
		BOOL	tryEmbeddedOnes = YES;
		
		if([aProtocol isEqualToString:@"http"]){
			launchPath = @"gpgkeys_http"; // Hardcoded
			aString = [@"/usr/local/libexec/gnupg/" stringByAppendingPathComponent:launchPath]; // Hardcoded
			tryEmbeddedOnes = ![[NSFileManager defaultManager] fileExistsAtPath:aString];
		}
		
		if(tryEmbeddedOnes){
			// Try to use embedded version - we should embed only gpg 1.2 version of these executables, as for gpg 1.4 all binaries are installed
#warning FIXME Emdeb gpgkeys_* 1.2 binaries (backwards compatible)
			launchPath = [[NSBundle bundleForClass:self] pathForResource:[launchPath stringByDeletingPathExtension] ofType:[launchPath pathExtension]]; // -pathForAuxiliaryExecutable: does not work for frameworks?!
			if(!launchPath || ![[NSFileManager defaultManager] fileExistsAtPath:launchPath]){
				[gpgOptions release];
				[[NSException exceptionWithGPGError:gpgme_error(GPGErrorKeyServerError) userInfo:[NSDictionary dictionaryWithObject:@"Unsupported keyserver type" forKey:GPGAdditionalReasonKey]] raise];
			}
		}
	}
    else
        launchPath = aString;

	formatVersionNumber = [executableVersions objectForKey:launchPath];
	if(!formatVersionNumber){
		// We need to test the format version used by the executable
		// We do it only once per executable and cache result,
		// to spare use of system resources (when launching task).
		NS_DURING
			NSData	*outputData;
			
			aTask = [[NSTask alloc] init];
			[aTask setLaunchPath:launchPath];
			[aTask setArguments:[NSArray arrayWithObject:@"-V"]]; // Get version
			anOutputPipe = [NSPipe pipe];
			[aTask setStandardOutput:[anOutputPipe fileHandleForWriting]];
			[aTask launch];
			// Output is on 2 lines: first contains format version,
			// second contains executable version; we are interested only in format version,
			// and reading first 2 bytes should be enough. If we use -readDataToEndOfFile
			// we need to write more complex code, to avoid being blocked.
			outputData = [[anOutputPipe fileHandleForReading] readDataOfLength:2];
			[aTask waitUntilExit];
			aString = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
			formatVersionNumber = [NSNumber numberWithInt:[aString intValue]];
			[executableVersions setObject:formatVersionNumber forKey:launchPath];
			[aString release];
			[aTask release];
		NS_HANDLER
			[aTask release];
			[gpgOptions release];
			[localException raise];
		NS_ENDHANDLER
	}

	formatVersion = [formatVersionNumber intValue];    
    aRange = [aHostName rangeOfString:@":"];
    if(aRange.length > 0){
        port = [aHostName substringFromIndex:aRange.location + 1];
        aHostName = [aHostName substringToIndex:aRange.location];
    }

    switch(theCommand){
        case _GPGContextHelperSearchCommand:
            commandString = [[NSMutableString alloc] initWithString:@"COMMAND search\n"]; break;
        case _GPGContextHelperGetCommand:
            commandString = [[NSMutableString alloc] initWithString:@"COMMAND get\n"]; break;
        case _GPGContextHelperUploadCommand:
            commandString = [[NSMutableString alloc] initWithString:@"COMMAND send\n"]; break;
    }
    [commandString appendFormat:@"HOST %@\n", aHostName];
    if(port != nil)
        [commandString appendFormat:@"PORT %@\n", port];

    if(formatVersion > 0)
        [commandString appendFormat:@"VERSION %d\n", formatVersion]; // For gpg >= 1.3.x, optional
    options = [thePassedOptions objectForKey:@"keyserver-options"];
    if(options == nil){
        options = [gpgOptions _subOptionsForName:@"keyserver-options"];
    }
    anEnum = [options objectEnumerator];

    while(aString = [anEnum nextObject]){
        [commandString appendFormat:@"OPTION %@\n", aString];
    }

    [commandString appendString:@"\n"]; // An empty line as separator
    switch(theCommand){
        case _GPGContextHelperGetCommand:
            [commandString appendString:[theArgument componentsJoinedByString:@"\n"]]; break;
        case _GPGContextHelperSearchCommand:
            // We cannot do a search with multiple patterns; we need to do multiple searches.
            // We start with the first pattern.
            [commandString appendString:[theArgument objectAtIndex:0]]; break;
        case _GPGContextHelperUploadCommand:{
            // We cannot upload multiple keys; we need to do multiple uploads.
            // We start with the first key.
            GPGKey		*aKey = [theArgument objectAtIndex:0];
            NSString	*aKeyID = [aKey keyID];
#warning FIXME Could we not use current context?
            GPGContext	*tempContext = [theContext copy];
            NSString	*asciiExport = nil;

            [tempContext setUsesArmor:YES];
            NS_DURING
                asciiExport = [[tempContext exportedKeys:[NSArray arrayWithObject:[aKey publicKey]]] string]; // NEVER send private key!!!
            NS_HANDLER
                [tempContext release];
                [commandString release];
                [gpgOptions release];
                [localException raise];
            NS_ENDHANDLER
            [commandString appendFormat:@"KEY %@ BEGIN\n%@\nKEY %@ END", aKeyID, asciiExport, aKeyID];
            [tempContext release];
            break;
        }
    }
    [commandString appendString:@"\n"]; // Terminate last line
    
    helper = [[self alloc] init];
    aTask = [[NSTask alloc] init];
    [aTask setLaunchPath:launchPath];

    inputPipe = [NSPipe pipe];
    anOutputPipe = [NSPipe pipe];
    anErrorPipe = [NSPipe pipe];
    [aTask setStandardInput:[inputPipe fileHandleForReading]];
    [aTask setStandardOutput:[anOutputPipe fileHandleForWriting]];
    [aTask setStandardError:[anErrorPipe fileHandleForWriting]];
    [[NSNotificationCenter defaultCenter] addObserver:helper selector:@selector(gotOutputResults:) name:NSFileHandleReadToEndOfFileCompletionNotification object:[anOutputPipe fileHandleForReading]];
    [[NSNotificationCenter defaultCenter] addObserver:helper selector:@selector(gotErrorResults:) name:NSFileHandleReadToEndOfFileCompletionNotification object:[anErrorPipe fileHandleForReading]];
    [[NSNotificationCenter defaultCenter] addObserver:helper selector:@selector(taskEnded:) name:NSTaskDidTerminateNotification object:aTask];
    [[anOutputPipe fileHandleForReading] readToEndOfFileInBackgroundAndNotify];
    [[anErrorPipe fileHandleForReading] readToEndOfFileInBackgroundAndNotify];

    helper->task = aTask;
    helper->context = [theContext retain];
    helper->argument = [theArgument copy];
    helper->outputPipe = [anOutputPipe retain];
    helper->errorPipe = [anErrorPipe retain];
    helper->hostName = [aHostName retain];
    helper->hostPort = [port retain];
    helper->protocolName = [aProtocol retain];
    helper->serverOptions = [options copy];
    helper->command = theCommand;
    helper->passedOptions = [thePassedOptions copy];
    helper->resultKeys = [[thePassedOptions objectForKey:@"_keys"] retain];
    if(helper->resultKeys == nil)
        helper->resultKeys = [[NSMutableArray alloc] init];
    helper->version = formatVersion;

    if(needsLocking)
        [_helperPerContextLock lock];
    NS_DURING
        NSMapInsertKnownAbsent(_helperPerContext, theContext, helper);
        switch(theCommand){
            case _GPGContextHelperGetCommand:
                [theContext setOperationMask:KeyDownloadOperation]; break;
            case _GPGContextHelperSearchCommand:
                [theContext setOperationMask:RemoteKeyListingOperation]; break;
            case _GPGContextHelperUploadCommand:
                [theContext setOperationMask:KeyUploadOperation]; break;
        }
        [[theContext operationData] setObject:commandString forKey:@"_command"]; // Useful for debugging

        [aTask launch];
        [[inputPipe fileHandleForWriting] writeData:[commandString dataUsingEncoding:NSUTF8StringEncoding]];
    NS_HANDLER
        gpgme_error_t	anError = gpgme_error(GPGErrorGeneralError);

        [[inputPipe fileHandleForWriting] closeFile];
        [gpgOptions release];
        [commandString release];
        [helper release];
        [[theContext operationData] setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
        NSMapRemove(_helperPerContext, theContext);
        if(needsLocking)
            [_helperPerContextLock unlock];
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:[localException reason] forKey:GPGAdditionalReasonKey]] raise];
    NS_ENDHANDLER

    [[inputPipe fileHandleForWriting] closeFile];
    [gpgOptions release];
    [commandString release];
    if(needsLocking)
        [_helperPerContextLock unlock];
    // helper will release itself after task terminates
}

+ (void) helpContext:(GPGContext *)theContext searchingForKeysMatchingPatterns:(NSArray *)theSearchPatterns serverOptions:(NSDictionary *)thePassedOptions
{
    [self performCommand:_GPGContextHelperSearchCommand forContext:theContext argument:theSearchPatterns serverOptions:thePassedOptions needsLocking:YES];
}

+ (void) helpContext:(GPGContext *)theContext downloadingKeys:(NSArray *)theKeys serverOptions:(NSDictionary *)options
{
    NSEnumerator	*anEnum = [theKeys objectEnumerator];
    GPGKey			*aKey;
    NSMutableArray	*patterns = [NSMutableArray array];

    while(aKey = [anEnum nextObject])
        [patterns addObject:[aKey keyID]];
    [self performCommand:_GPGContextHelperGetCommand forContext:theContext argument:patterns serverOptions:options needsLocking:YES];
}

+ (void) helpContext:(GPGContext *)theContext uploadingKeys:(NSArray *)theKeys serverOptions:(NSDictionary *)options
{
    [self performCommand:_GPGContextHelperUploadCommand forContext:theContext argument:theKeys serverOptions:options needsLocking:YES];
}

- (void) interrupt
{
    interrupted = YES;
    [task interrupt];
}

- (void) taskEnded:(NSNotification *)notification
{
    [[outputPipe fileHandleForWriting] closeFile]; // Needed, else is blocking on read()!
    [[errorPipe fileHandleForWriting] closeFile]; // Needed, else is blocking on read()!
    [[NSNotificationCenter defaultCenter] removeObserver:self name:[notification name] object:[notification object]];
}

- (NSArray *) keysFromOutputString:(NSString *)outputString
{
    NSEnumerator		*anEnum = [[outputString componentsSeparatedByString:@"\n"] objectEnumerator];
    NSString			*aLine;
    int					aCount = -1;
    NSMutableDictionary	*linesPerKeyID = [NSMutableDictionary dictionary];
    int					aVersion = 0;

    while(aLine = [anEnum nextObject]){
        if([aLine hasPrefix:@"VERSION "])
            aVersion = [[aLine substringFromIndex:8] intValue];
        else if([aLine hasPrefix:@"COUNT "]){
            // Used only for version 0, currently
            int	i = 0;

            NSAssert(aVersion == 0, @"### Unknown output format if not version 0 ###");
            aCount = [[aLine substringFromIndex:6] intValue];
            for(; i < aCount; i++){
                int				anIndex;
                NSString		*aKeyID;
                NSMutableArray	*anArray;

                aLine = [anEnum nextObject];
                anIndex = [aLine rangeOfString:@":"].location;
                aKeyID = [aLine substringToIndex:anIndex];
                anArray = [linesPerKeyID objectForKey:aKeyID];
                if(anArray == nil)
                    [linesPerKeyID setObject:[NSMutableArray arrayWithObject:aLine] forKey:aKeyID];
                else
                    [anArray addObject:aLine];
            }
            break;
        }
        else if([aLine hasPrefix:@"info:1:"]){
            // Followed by a number telling how many public keys are listed
            // Used only for version 1, currently, but optional!
            NSAssert(aVersion == 1, @"### Unknown output format if not version 1 ###");
            aCount = [[aLine substringFromIndex:7] intValue];
        }
        else if([aLine hasPrefix:@"pub:"]){
            // Used only for version 1, currently
            int	i = 0;
            BOOL	hadCount = (aCount > 0);

            NSAssert(aVersion == 1, @"### Unknown output format if not version 1 ###");
            if(!hadCount)
                aCount = 1;
            for(; i < aCount; i++){
                if([aLine hasPrefix:@"pub:"]){
                    int				anIndex;
                    unsigned		aLength = [aLine length];
                    NSString		*aKeyID;
                    NSMutableArray	*anArray;

                    anIndex = [aLine rangeOfString:@":" options:0 range:NSMakeRange(4, aLength - 4)].location;
                    aKeyID = [aLine substringWithRange:NSMakeRange(4, aLength - anIndex)];
                    anArray = [NSMutableArray arrayWithObject:aLine];
                    [linesPerKeyID setObject:anArray forKey:aKeyID];
                    while(aLine = [anEnum nextObject]){
                        if([aLine hasPrefix:@"uid:"])
                            [anArray addObject:aLine];
                        else if([aLine hasPrefix:@"pub:"]){
                            if(!hadCount)
                                aCount++;
                            break;
                        }
                        else if([aLine hasPrefix:@"SEARCH "] || [aLine length] == 0)
                            // SEARCH ... END
                            break;
                        else if(![aLine isEqualToString:@"\r"])
                            NSLog(@"### Unable to parse following line. Ignored.\n%@", aLine);
                    }
                }
                else
                    NSLog(@"### Expecting 'pub:' prefix in following line. Ignored.\n%@", aLine);

            }
            break;
        }
//        else if([aLine hasPrefix:@"SEARCH "] && [aLine rangeOfString:@" FAILED "].location != NSNotFound){
//        }
//        else if([aLine hasPrefix:@"KEY 0x"] && [aLine rangeOfString:@" FAILED "].location != NSNotFound){
//        }
    }
    if(aCount == -1)
        return nil;
    else{
        NSArray			*anArray;
        NSMutableArray	*keys = [NSMutableArray array];

        anEnum = [linesPerKeyID objectEnumerator]; // We loose the order; no cure.
        while(anArray = [anEnum nextObject]){
            GPGRemoteKey	*aKey = [[GPGRemoteKey alloc] initWithColonOutputStrings:anArray version:aVersion];
            
            [keys addObject:aKey];
            [aKey release];
        }
        return keys;
    }
}

- (void) postNotificationInMainThread:(NSNotification *)notification
{
    [[[notification object] operationData] setObject:[[notification userInfo] objectForKey:GPGErrorKey] forKey:GPGErrorKey];
    [[NSNotificationCenter defaultCenter] postNotification:notification];
}

- (void) passResultsBackFromData:(NSMutableDictionary *)dict
{
    // Executed in main thread
    GPGError	anError = GPGErrorNoError;
    NSData		*readData = [dict objectForKey:@"readData"];

    switch(command){
        case _GPGContextHelperGetCommand:{
            anError = [context _importKeyDataFromServerOutput:readData];
            break;
        }
        case _GPGContextHelperSearchCommand:{
            // It happens that output data is a mix of correct UTF8 userIDs
            // and invalid ISOLatin1 userIDs! If we decode using UTF8, it will fail,
            // and all UTF8 userIDs will be displayed badly, because decoded as ISOLatin1.
            // We need to decode one line after the other.
            const unsigned char *bytes = [readData bytes];
            const unsigned char *readPtr = bytes;
            const unsigned char *endPtr = (bytes + [readData length]);
            NSMutableArray      *lines = [[NSMutableArray alloc] init];
            NSString            *rawResults;
            NSArray             *keys;

            while(readPtr < endPtr){
                // We consider that line endings contain \n (works also for \r\n)
                const unsigned char *aPtr = memchr(readPtr, '\n', endPtr - readPtr);
                NSString            *aLine;
                NSData				*lineData;
                
                if(aPtr == NULL)
                    aPtr = endPtr;

                lineData = [[NSData alloc] initWithBytes:readPtr length:(aPtr - readPtr)];
                aLine = [[NSString alloc] initWithData:lineData encoding:NSUTF8StringEncoding];
                
                if(aLine == nil)
                    // We consider that if we cannot decode string as UTF-8 encoded,
                    // then we use ISOLatin1 encoding.
                    aLine = [[NSString alloc] initWithData:lineData encoding:NSISOLatin1StringEncoding];
                [lines addObject:aLine];
                readPtr = aPtr + 1;
                [lineData release];
                [aLine release];
            }
            
            rawResults = [lines componentsJoinedByString:@"\n"];
            keys = [self keysFromOutputString:rawResults];

            if(keys != nil){
                // Support for multiple search patterns
                [resultKeys addObjectsFromArray:keys];
                [dict setObject:resultKeys forKey:@"_keys"];
                [[context operationData] setObject:resultKeys forKey:@"keys"];
            }
            [lines release];
        }
        case _GPGContextHelperUploadCommand:{
            // Parse output to find out if everything went fine
            // and add uploaded key to [dict setObject:resultKeys forKey:@"_keys"]
        }            
    }

    [[context operationData] setObject:hostName forKey:@"hostName"];
    [[context operationData] setObject:protocolName forKey:@"protocol"];
    [[context operationData] setObject:serverOptions forKey:@"options"];
    if(hostPort)
        [[context operationData] setObject:hostPort forKey:@"port"];
    [dict setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
}

- (void) startSearchForNextPattern:(NSArray *)fetchedKeys
{
    // Executed in main thread
    NSMutableDictionary *aDict = [NSMutableDictionary dictionaryWithDictionary:passedOptions];
    
    [aDict setObject:fetchedKeys forKey:@"_keys"];
    NSMapRemove(_helperPerContext, context);
    [[self class] performCommand:command forContext:context argument:[argument subarrayWithRange:NSMakeRange(1, [argument count] - 1)] serverOptions:aDict needsLocking:NO];
}

- (void) startUploadForNextKey:(NSArray *)uploadedKeys
{
    // Executed in main thread
    NSMutableDictionary *aDict = [NSMutableDictionary dictionaryWithDictionary:passedOptions];

    [aDict setObject:uploadedKeys forKey:@"_keys"];
    NSMapRemove(_helperPerContext, context);
    [[self class] performCommand:command forContext:context argument:[argument subarrayWithRange:NSMakeRange(1, [argument count] - 1)] serverOptions:aDict needsLocking:NO];
}

- (void) gotErrorResults:(NSNotification *)notification
{
    // WARNING: might be executed in a secondary thread
    NSData		*readData = [[notification userInfo] objectForKey:NSFileHandleNotificationDataItem];
    NSString	*aString = [[NSString alloc] initWithData:readData encoding:NSUTF8StringEncoding];
    
    NSLog(@"%@", aString);
#warning TODO parse results and returns them in exception, if any
    [aString release];
}

- (void) gotOutputResults:(NSNotification *)notification
{
    // WARNING: might be executed in a secondary thread
    NSNotification	*aNotification = nil;

    [_helperPerContextLock lock];
    NS_DURING
        int	terminationStatus = [task terminationStatus];
        
        [[NSNotificationCenter defaultCenter] removeObserver:self name:[notification name] object:[notification object]];

        if(!interrupted){
            if(terminationStatus != 0){
                // In case of multiple search patterns, we stop after first error
                gpgme_error_t	anError = gpgme_error(GPGErrorKeyServerError);

                aNotification = [NSNotification notificationWithName:GPGAsynchronousOperationDidTerminateNotification object:context userInfo:[NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey]];
            }
            else{
                NSData				*readData = [[notification userInfo] objectForKey:NSFileHandleNotificationDataItem];
                NSMutableDictionary	*passedData = [NSMutableDictionary dictionaryWithObject:readData forKey:@"readData"];
                unsigned            aCount = [argument count];

                [self performSelectorOnMainThread:@selector(passResultsBackFromData:) withObject:passedData waitUntilDone:YES];

                if(command == _GPGContextHelperSearchCommand && aCount > 1)
                    [self performSelectorOnMainThread:@selector(startSearchForNextPattern:) withObject:[passedData objectForKey:@"_keys"] waitUntilDone:YES];
                else if(command == _GPGContextHelperUploadCommand && aCount > 1)
                        [self performSelectorOnMainThread:@selector(startUploadForNextKey:) withObject:[passedData objectForKey:@"_keys"] waitUntilDone:YES];
                else
                    aNotification = [NSNotification notificationWithName:GPGAsynchronousOperationDidTerminateNotification object:context userInfo:[NSDictionary dictionaryWithObject:[passedData objectForKey:GPGErrorKey] forKey:GPGErrorKey]];
            }
        }
        else{
            // When interrupted, when send notif anyway with error?
            gpgme_error_t	anError = gpgme_error(GPG_ERR_CANCELED);

            aNotification = [NSNotification notificationWithName:GPGAsynchronousOperationDidTerminateNotification object:context userInfo:[NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey]];
        }
    NS_HANDLER
        NSMapRemove(_helperPerContext, context);
        [self autorelease];
        [_helperPerContextLock unlock];
        [localException raise];
    NS_ENDHANDLER

    if(aNotification != nil){
        NSMapRemove(_helperPerContext, context);
        [_helperPerContextLock unlock];
        [self performSelectorOnMainThread:@selector(postNotificationInMainThread:) withObject:aNotification waitUntilDone:YES];
    }
    else
        [_helperPerContextLock unlock];

    [self release];
}

- (void) dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [context release];
    [task release];
    [argument release];
    [outputPipe release];
    [errorPipe release];
    [hostName release];
    [hostPort release];
    [protocolName release];
    [serverOptions release];
    [passedOptions release];
    [resultKeys release];

    [super dealloc];
}

@end


@implementation GPGContext(GPGExtendedKeyManagement)

- (void) asyncSearchForKeysMatchingPatterns:(NSArray *)searchPatterns serverOptions:(NSDictionary *)options
// FIXME Are there any new options with gpg 1.4?
/*"
 * Contacts asynchronously a key server and asks it for keys matching 
 * searchPatterns.
 *
 * The options dictionary can contain the following key-value pairs:
 * _{@"keyserver"          A keyserver URL, e.g. ldap://keyserver.pgp.com or
 *                         x-hkp://keyserver.pgp.com:8000; if keyserver is not
 *                         set, the default keyserver, from gpg configuration,
 *                         is used.}
 * _{@"keyserver-options"  An array which can contain the following string
 *                         values: @"include-revoked", @"include-disabled",
 *                         @"honor-http-proxy", @"broken-http-proxy",
 *                         @"try-dns-srv" or the same options but prefixed by
 *                         @"no-". If this pair is not given, values are taken
 *                         from gpg configuration. Not all types of servers
 *                         support all these options, but unsupported ones are
 *                         silently ignored.}
 *
 * A #GPGAsynchronousOperationDidTerminateNotification notification will be 
 * sent on completion of the operation, be it successful or not. The object is
 * the context, and the results can be retrieved from #{-operationResults}.
 *
 * Once you got results, you can invoke #{asyncDownloadKeys:serverOptions:} 
 * passing for example a subset of the keys returned from the search.
 *
 * Method cannot be used yet to search CMS keys.
 *
 * Can raise a #GPGException:
 * _{GPGErrorKeyServerError  gpg is not configured correctly. More information
 *                           in #GPGAdditionalReasonKey userInfo key}
 * _{GPGErrorGeneralError    An unknown error occurred during search. More
 *                           information in #GPGAdditionalReasonKey userInfo
 *                           key}
"*/
{
    // TODO Add support for multiple keyservers: combine results, and stop when all tasks stopped
    NSParameterAssert(searchPatterns != nil && [searchPatterns count] > 0);

    if([self protocol] != GPGOpenPGPProtocol)
        [[NSException exceptionWithGPGError:gpgme_error(GPGErrorNotImplemented) userInfo:nil] raise];

    [_GPGContextHelper helpContext:self searchingForKeysMatchingPatterns:searchPatterns serverOptions:options];
}

- (void) asyncDownloadKeys:(NSArray *)keys serverOptions:(NSDictionary *)options
/*"
 * Contacts asynchronously a key server and download keys from it. This method
 * is usually invoked after having searched for keys on the server, and is
 * passed a subset of the #GPGRemoteKey instances returned by the search.
 * Received keys are then automatically imported in default key-ring. Note that
 * you can also pass keys from user's key-ring (#GPGKey instances) to refresh them.
 *
 * The options dictionary can contain the following key-value pairs:
 * _{@"keyserver"          A keyserver URL, e.g. ldap://keyserver.pgp.com or
 *                         x-hkp://keyserver.pgp.com:8000; if keyserver is not
 *                         set, the default keyserver, from gpg configuration,
 *                         is used.}
 * _{@"keyserver-options"  An array which can contain the following string
 *                         values: @"include-revoked", @"include-disabled",
 *                         @"honor-http-proxy", @"broken-http-proxy",
 *                         @"try-dns-srv" or the same options but prefixed by
 *                         @"no-". If this pair is not given, values are taken
 *                         from gpg configuration. Not all types of servers
 *                         support all these options, but unsupported ones are
 *                         silently ignored.}
 *
 * A #GPGAsynchronousOperationDidTerminateNotification notification will be
 * sent on completion of the operation, be it successful or not. The object is
 * the context. See #{-operationResults} to get imported keys.
 *
 * Downloaded keys will be automatically imported in your default key-ring,
 * and a #GPGKeyringChangedNotification notification will be posted, like for
 * an import operation. See #{importKeyData:} for more information about this
 * notification and how to get downloaded keys.
 *
 * Method cannot be used yet to download CMS keys.
 *
 * Can raise a #GPGException:
 * _{GPGErrorInvalidValue  gpg is not configured correctly.
 *                         More information in #GPGAdditionalReasonKey userInfo key}
 * _{GPGErrorGeneralError  An unknown error occurred during search.
 *                         More information in #GPGAdditionalReasonKey userInfo key}
"*/
{
    NSParameterAssert(keys != nil && [keys count] > 0);

    if([self protocol] != GPGOpenPGPProtocol)
        [[NSException exceptionWithGPGError:gpgme_error(GPGErrorNotImplemented) userInfo:nil] raise];
    [_GPGContextHelper helpContext:self downloadingKeys:keys serverOptions:options];
}

- (GPGError) _importKeyDataFromServerOutput:(NSData *)result
{
    // We don't need to parse rawData: keys are ASCII-armored,
    // and gpg is able to recognize armors :-)
    GPGData				*keyData = [[GPGData alloc] initWithData:result];
    NSMutableDictionary	*savedOperationData = [_operationData mutableCopy];
    int					savedOperationMask = _operationMask;
    GPGError			resultError = GPGErrorNoError;
    
    [keyData setEncoding:GPGDataEncodingArmor];
    NS_DURING
        // WARNING: this changes operation mask & data!
        (void)[self importKeyData:keyData];
    NS_HANDLER
        // Should we pass error back to result?
        if([[localException name] isEqualToString:GPGException])
            resultError = [[[localException userInfo] objectForKey:GPGErrorKey] unsignedIntValue];
        else
            [localException raise];
    NS_ENDHANDLER
    [keyData release];
    _operationMask |= savedOperationMask;
    [_operationData addEntriesFromDictionary:savedOperationData];

    return resultError;
}

- (void) asyncUploadKeys:(NSArray *)keys serverOptions:(NSDictionary *)options
/*"
 * Contacts asynchronously a key server to uploads keys. Only public keys are
 * uploaded: if you pass, by mistake, a secret key, method will upload the
 * public key, not the secret one.
 *
 * The options dictionary can contain the following key-value pairs:
 * _{@"keyserver"          A keyserver URL, e.g. ldap://keyserver.pgp.com or
 *                         x-hkp://keyserver.pgp.com:8000; if keyserver is not
 *                         set, the default keyserver, from gpg configuration,
 *                         is used.}
 * _{@"keyserver-options"  An array which can contain the following string
 *                         values: @"include-revoked", @"include-disabled",
 *                         @"honor-http-proxy", @"broken-http-proxy",
 *                         @"try-dns-srv" or the same options but prefixed by
 *                         @"no-". If this pair is not given, values are taken
 *                         from gpg configuration. Not all types of servers
 *                         support all these options, but unsupported ones are
 *                         silently ignored.}
 *
 * A #GPGAsynchronousOperationDidTerminateNotification notification will be
 * sent on completion of the operation, be it successful or not. The object is
 * the context, and the results can be retrieved from #{-operationResults}.
 *
 * Method cannot be used yet to search CMS keys.
 *
 * Can raise a #GPGException:
 * _{GPGErrorKeyServerError  gpg is not configured correctly. More information
 *                           in #GPGAdditionalReasonKey userInfo key}
 * _{GPGErrorGeneralError    An unknown error occurred during search. More
 *                           information in #GPGAdditionalReasonKey userInfo
 *                           key}
"*/
{
#warning TEST!
//    [[NSException exceptionWithGPGError:gpgme_error(GPGErrorNotImplemented) userInfo:nil] raise];
    NSParameterAssert(keys != nil && [keys count] > 0);

    if([self protocol] != GPGOpenPGPProtocol)
        [[NSException exceptionWithGPGError:gpgme_error(GPGErrorNotImplemented) userInfo:nil] raise];
    [_GPGContextHelper helpContext:self uploadingKeys:keys serverOptions:options];
}

- (void) interruptAsyncOperation
/*"
 * Interrupts asynchronous operation. The
 * #GPGAsynchronousOperationDidTerminateNotification notification will be sent
 * with the error code #GPGErrorCancelled. This method can be used to interrupt
 * only the -async* methods. After interrupt, you can still ask the context for
 * the operation results; you might get valid partial results. No error is
 * returned when context is not running an async operation, or operation has
 * already finished.
"*/
{
    _GPGContextHelper	*helper;
    
    [_helperPerContextLock lock];
    NS_DURING
        helper = NSMapGet(_helperPerContext, self);
        if(helper != nil)
            [helper interrupt];
    NS_HANDLER
        [_helperPerContextLock unlock];
        [localException raise];
    NS_ENDHANDLER
    [_helperPerContextLock unlock];
}


- (BOOL) isPerformingAsyncOperation
/*"
 * If the context is processing an async operation, this method will return YES.
 * Otherwise, it will return NO.
"*/
{
    return (NSMapGet(_helperPerContext, self) != nil);
}

@end


@implementation GPGContext(GPGKeyGroups)

- (NSArray *) keyGroups
/*"
 * Returns all groups defined in gpg.conf.
"*/
{
    GPGOptions          *options = [[GPGOptions alloc] init];
    NSArray             *groupOptionValues = [options activeOptionValuesForName:@"group"];
    NSEnumerator        *groupDefEnum = [groupOptionValues objectEnumerator];
    NSMutableDictionary *groupsPerName = [NSMutableDictionary dictionaryWithCapacity:[groupOptionValues count]];
    NSString            *aGroupDefinition;
    
    while((aGroupDefinition = [groupDefEnum nextObject]) != nil){
        NSDictionary    *aDict = [[self class] parsedGroupDefinitionLine:aGroupDefinition];
        GPGKeyGroup     *newGroup;
        NSString        *aName;
        NSArray         *keys;
        NSArray         *additionalKeys = nil;
        
        if(aDict == nil)
            continue;
        
        aName = [aDict objectForKey:@"name"];
        newGroup = [groupsPerName objectForKey:aName];
        if(newGroup){
            // Multiple groups with the same name are automatically merged
            // into a single group.
            additionalKeys = [newGroup keys];
        }
                
        keys = [aDict objectForKey:@"keys"];
        if([keys count] > 0)
            keys = [[self keyEnumeratorForSearchPatterns:keys secretKeysOnly:NO] allObjects];

        newGroup = [[GPGKeyGroup alloc] initWithName:aName keys:(additionalKeys ? [additionalKeys arrayByAddingObjectsFromArray:keys] : keys)];
        
        [groupsPerName setObject:newGroup forKey:aName];
        [newGroup release];
    }
    
    [options release];
    
    return [groupsPerName allValues];
}

@end

@implementation GPGContext(GPGInternals)

- (gpgme_ctx_t) gpgmeContext
{
    return _context;
}

- (void) setOperationMask:(int)flags
{
    _operationMask = flags;
    [_operationData removeAllObjects];
}

- (NSMutableDictionary *) operationData
{
    return _operationData;
}

+ (NSDictionary *) parsedGroupDefinitionLine:(NSString *)groupDefLine
{
    int         anIndex = [groupDefLine rangeOfString:@"="].location;
    NSString    *aName;
    
    if(anIndex == NSNotFound){
        NSLog(@"### Invalid group definition:\n%@", groupDefLine);
        return nil; // This is an invalid group definition! Let's ignore it
    }
    
    aName = [groupDefLine substringToIndex:anIndex];
    aName = [aName stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if([aName length] == 0){
        NSLog(@"### Invalid group definition - empty name:\n%@", groupDefLine);
        return nil; // This is an invalid group definition! Let's ignore it
    }
    
    if(anIndex < ([groupDefLine length] - 1)){
        // We accept only keyIDs or fingerprints, separated by a space or a tab
        NSMutableString *aString = [NSMutableString stringWithString:[[groupDefLine substringFromIndex:anIndex + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]];
        
        [aString replaceOccurrencesOfString:@"\t" withString:@" " options:0 range:NSMakeRange(0, [aString length])];
        while([aString replaceOccurrencesOfString:@"  " withString:@" " options:0 range:NSMakeRange(0, [aString length])] != 0)
            ;
        
        return [NSDictionary dictionaryWithObjectsAndKeys:[aString componentsSeparatedByString:@" "], @"keys", aName, @"name", nil];
    }
    else
        return [NSDictionary dictionaryWithObjectsAndKeys:[NSArray array], @"keys", aName, @"name", nil];
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
    gpgme_key_t	aKey = gpgme_signers_enum([context gpgmeContext], index); // Acquires a reference to the signers key with the specified index
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
        gpgme_error_t	anError;
        const char		*aPattern = (searchPattern != nil ? [searchPattern UTF8String]:NULL);

        anError = gpgme_op_keylist_start([newContext gpgmeContext], aPattern, secretKeysOnly);
        [newContext setOperationMask:KeyListingOperation];
        [[newContext operationData] setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];

        if(anError != GPG_ERR_NO_ERROR){
            [self release];
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        }
        else
            // We retain newContext, to avoid it to be released before we have finished
            context = [newContext retain];
    }

    return self;
}

- (id) initForContext:(GPGContext *)newContext searchPatterns:(NSArray *)searchPatterns secretKeysOnly:(BOOL)secretKeysOnly
{
    NSParameterAssert(searchPatterns != nil);
    
    if(self = [self init]){
        gpgme_error_t	anError;
        int				i, patternCount = [searchPatterns count];
        const char		**patterns;

        patterns = NSZoneMalloc(NSDefaultMallocZone(), (patternCount + 1) * sizeof(char *));
        for(i = 0; i < patternCount; i++)
            patterns[i] = [[searchPatterns objectAtIndex:i] UTF8String];
        patterns[i] = NULL;

        anError = gpgme_op_keylist_ext_start([newContext gpgmeContext], patterns, secretKeysOnly, 0);
        [newContext setOperationMask:KeyListingOperation];
        [[newContext operationData] setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];
        NSZoneFree(NSDefaultMallocZone(), patterns);

        if(anError != GPG_ERR_NO_ERROR){
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
    gpgme_error_t	anError = GPG_ERR_NO_ERROR;
    
    if(context != nil){
        anError = gpgme_op_keylist_end([context gpgmeContext]);
        // We don't care about the key listing operation result
        [context autorelease]; // Do not release it, we might need it for exception
    }

    [super dealloc];

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:context forKey:GPGContextKey]] raise];
}

- (id) nextObject
{
    gpgme_key_t		aKey;
    gpgme_error_t	anError;

    NSAssert(context != nil, @"### Enumerator is invalid now, because an exception was raised during enumeration.");
    anError = gpgme_op_keylist_next([context gpgmeContext], &aKey); // Returned key has one reference
    if(gpg_err_code(anError) == GPG_ERR_EOF){
        gpgme_keylist_result_t	result = gpgme_op_keylist_result([context gpgmeContext]);

        if(!!result->truncated)
            [[NSException exceptionWithGPGError:GPGMakeError(GPG_MacGPGMEFrameworkErrorSource, GPGErrorTruncatedKeyListing) userInfo:[NSDictionary dictionaryWithObject:context forKey:GPGContextKey]] raise];
        return nil;
    }
    
    if(anError != GPG_ERR_NO_ERROR){
        // We release and nullify context; we don't want another exception
        // being raised during -dealloc, as we call gpgme_op_keylist_end().
        GPGContext	*aContext = context;

        context = nil;
        [aContext autorelease]; // Do not release it: we need it for exception
        [[NSException exceptionWithGPGError:anError userInfo:[NSDictionary dictionaryWithObject:aContext forKey:GPGContextKey]] raise];
    }

    NSAssert(aKey != NULL, @"### Returned key is NULL, but no error?!");

    return [[[GPGKey alloc] initWithInternalRepresentation:aKey] autorelease];
}

@end


@implementation GPGTrustItemEnumerator

- (id) initForContext:(GPGContext *)newContext searchPattern:(NSString *)searchPattern maximumLevel:(int)maxLevel
{
    NSParameterAssert(searchPattern != nil && [searchPattern length] > 0);
    
    if(self = [self init]){
        gpgme_error_t	anError;
        const char		*aPattern = [searchPattern UTF8String];

        anError = gpgme_op_trustlist_start([newContext gpgmeContext], aPattern, maxLevel);
        [newContext setOperationMask:TrustItemListingOperation];
        [[newContext operationData] setObject:[NSNumber numberWithUnsignedInt:anError] forKey:GPGErrorKey];

        if(anError != GPG_ERR_NO_ERROR){
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
    gpgme_error_t	anError;

    if(context != nil){
        anError = gpgme_op_trustlist_end([context gpgmeContext]);
        [context release];
    }
    else
        anError = GPG_ERR_NO_ERROR;

    [super dealloc];

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (id) nextObject
{
    gpgme_trust_item_t	aTrustItem;
    gpgme_error_t		anError = gpgme_op_trustlist_next([context gpgmeContext], &aTrustItem);

    // Q: Does it really return a GPG_ERR_EOF?
    // Answer from Werner: "It should, but well I may have to change things. Don't spend too much time on it yet."
    if(gpg_err_code(anError) == GPG_ERR_EOF)
        return nil;

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    NSAssert(aTrustItem != NULL, @"### Returned trustItem is NULL, but no error?!");

    return [[[GPGTrustItem alloc] initWithInternalRepresentation:aTrustItem] autorelease];
}

@end


// We need to write this fake implementation (not compiled!)
// just to force autodoc to take our comments in account!
#ifdef FAKE_IMPLEMENTATION_FOR_AUTODOC

@implementation NSObject(GPGContextDelegate)
- (NSString *) context:(GPGContext *)context passphraseForKey:(GPGKey *)key again:(BOOL)again
/*"
 * key is the secret key for which the user is asked a passphrase. key is nil
 * only in case of symmetric encryption/decryption. again is set to YES if
 * user typed a wrong passphrase the previous time(s).
 *
 * If you return nil, it means that user cancelled passphrase request.
"*/
{
}
@end

#endif

