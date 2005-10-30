//
//  GPGSignature.m
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Sun Jul 14 2002.
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

#include <MacGPGME/GPGSignature.h>
#include <MacGPGME/GPGPrettyInfo.h>
#include <MacGPGME/GPGSignatureNotation.h>
#include <MacGPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


@implementation GPGSignature
/*"
 * #GPGSignature instances are returned by #{-[GPGContext signatures]}; you
 * should never need to instantiate yourself objects of that class. Signatures
 * are also returned after a signing operation, but in this case, currently,
 * not all attributes have significant values: you can count only on
 * -algorithm, -hashAlgorithm, -signatureClass, -creationDate and -fingerprint
"*/

+ (BOOL) accessInstanceVariablesDirectly
{
    return NO;
}

- (void) dealloc
{
    [_fingerprint release];
    [_creationDate release];
    [_expirationDate release];
    [_notations release];
    [_policyURLs release];
    [_signatureNotations release];

    [super dealloc];
}

- (id) copyWithZone:(NSZone *)zone
/*"
 * Returns the same instance, retained. #GPGSignature instances are
 * (currently) immutable.
 *
 * #WARNING: zone is not taken in account.
"*/
{
    // Implementation is useful to allow use of GPGSignature instances as keys in NSMutableDictionary instances.
    return [self retain];
}

- (NSString *) fingerprint
/*"
 * Returns signer's key %fingerprint (or keyID!).
"*/
{
    return _fingerprint;
}

- (NSString *) formattedFingerprint
/*"
 * If -fingerprint returns a fingerprint, returns %{fingerprint} in hex digit
 * form, formatted like this:
 *
 * XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
 *
 * or
 *
 * XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX
 *
 * If -fingerprint returns a keyID, return keyID prefixed by 0x.
"*/
{
    NSString	*aString = [self fingerprint];

    if(aString == nil)
        return @"";
    else if([aString length] >= 32)
        return [GPGKey formattedFingerprint:aString];
    else
        return [@"0x" stringByAppendingString:aString];
}

- (GPGError) validityError
/*"
 * If a signature is not valid, this provides a reason why. Not used for new
 * signatures.
"*/
{
    return _validityError;
}

- (BOOL) wrongKeyUsage
/*"
 * Returns YES if the key was not used according to its policy. Not used for
 * new signatures.
"*/
{
    return _wrongKeyUsage;
}

- (NSCalendarDate *) creationDate
/*"
 * Returns %signature creation date. Returns nil when not available or
 * invalid.
"*/
{
    return _creationDate;
}

- (NSCalendarDate *) expirationDate
/*"
 * Returns %signature expiration date. Returns nil if signature does not
 * expire. Not used for new signatures.
"*/
{
    return _expirationDate;
}

- (GPGValidity) validity
/*"
 * Returns %signature's validity. Not used for new signatures.
 *
 * Note that a signature's validity is never #GPGValidityUltimate, because
 * #GPGValidityUltimate is reserved for key certification, not for signatures.
"*/
{
    return _validity;
}

- (NSString *) validityDescription
/*"
 * Returns %signature's validity in localized human readable form. Not used
 * for new signatures.
"*/
{
    return GPGValidityDescription([self validity]);
}

- (GPGError) status
/*"
 * Returns %signature status. In particular, the following status codes are of
 * interest:
 * _{GPGErrorNoError             This status indicates that the signature is
 *                               valid. For the combined result this status
 *                               means that all signatures are valid.}
 * _{GPGErrorSignatureExpired    This status indicates that the signature is
 *                               valid but expired. For the combined result this
 *                               status means that all signatures are valid and
 *                               expired.}
 * _{GPGErrorKeyExpired          This status indicates that the signature is
 *                               valid but the key used to verify the signature
 *                               has expired. For the combined result this
 *                               status means that all signatures are valid and
 *                               all keys are expired.}
 * _{GPGErrorCertificateRevoked  This status indicates that the signature is
 *                               valid but the key used  to verify the signature
 *                               has been revoked. For the combined result this
 *                               status means that all signatures are valid and
 *                               all keys are  revoked.}
 * _{GPGErrorBadSignature        This status indicates that the signature is
 *                               invalid. For the combined result this status
 *                               means that all signatures are invalid.}
 * _{GPGErrorNoPublicKey         This status indicates that the signature could
 *                               not be verified due to a missing key. For the
 *                               combined result this status means that all
 *                               signatures could not be checked due to missing
 *                               keys.}
 * _{GPGErrorGeneralError        This status indicates that there was some other
 *                               error which prevented the signature
 *                               verification.}
 * Not used for new signatures.
"*/
{
    return _status;
}

- (GPGSignatureSummaryMask) summary
/*"
 * Returns a mask giving a summary of the signature status. Not used for new
 * signatures.
"*/
{
    return _summary;
}

- (GPGPublicKeyAlgorithm) algorithm
/*"
 * Returns the public key algorithm used to create the signature.
"*/
{
    return _algorithm;
}

- (NSString *) algorithmDescription
/*"
 * Returns the localized description of the public key algorithm used to create
 * the signature.
"*/
{
    return GPGLocalizedPublicKeyAlgorithmDescription([self algorithm]);
}

- (GPGHashAlgorithm) hashAlgorithm
/*"
 * Returns the hash algorithm used for the signature.
"*/
{
    return _hashAlgorithm;
}

- (NSString *) hashAlgorithmDescription
/*"
 * Returns the localized description of the hash algorithm used for the
 * signature.
"*/
{
    return GPGLocalizedHashAlgorithmDescription([self hashAlgorithm]);
}

- (unsigned int) signatureClass
/*"
 * Returns the signature class of a %{key signature} or a new signature. The
 * meaning is specific to the crypto engine.
 *
 * This attribute is not (yet?) available for signatures returned after a
 * verification operation.
"*/
{
    return _signatureClass;
}

- (NSArray *) signatureNotations
/*"
 * Returns all signature notations (notation data and policy URLs).   
"*/
{
    return _signatureNotations;
}

@end


@implementation GPGSignature(GPGSignatureDeprecated)

- (NSDictionary *) notations
/*"
 * Returns a dictionary of %{notation data} key-value pairs. A notation is a
 * key/value pair that is added to the content, it can be anything. Value
 * is returned as an NSString instance. Not used for new signatures.
 *
 * #DEPRECATED: use -signatureNotations instead.
"*/
{
    return _notations;
}

- (NSArray *) policyURLs
/*"
 * Returns an array of %{policy URLs} as NSString instances. A policy URL is
 * an URL to a document that documents the persons policy in signing other
 * peoples keys. Not used for new signatures.
 *
 * #DEPRECATED: use -signatureNotations instead.
"*/
{
    return _policyURLs;
}

@end


@implementation GPGSignature(GPGInternals)

- (id) initWithSignature:(gpgme_signature_t)signature
{
    if(self = [self init]){
        unsigned long			aValue;
        gpgme_sig_notation_t	aNotation;

        _fingerprint = [GPGStringFromChars(signature->fpr) retain];
        _validityError = signature->validity_reason;
        _wrongKeyUsage = !!signature->wrong_key_usage;
        aValue = signature->timestamp;
        if(aValue != 0L)
            _creationDate = [[NSCalendarDate dateWithTimeIntervalSince1970:aValue] retain];
        aValue = signature->exp_timestamp;
        if(aValue != 0L)
            _expirationDate = [[NSCalendarDate dateWithTimeIntervalSince1970:aValue] retain];
        _validity = signature->validity;
        _status = signature->status;
        _summary = signature->summary;
        aNotation = signature->notations;
        _notations = [[NSMutableDictionary alloc] init];
        _policyURLs = [[NSMutableArray alloc] init];
        _signatureNotations = [[NSMutableArray alloc] init];
        while(aNotation != NULL){
            char                    *name = aNotation->name;
            GPGSignatureNotation    *anObject;
            
            if(name != NULL){
                // WARNING: theoretically there could be more than one notation
                // data for the same name.
                NSString	*aName = GPGStringFromChars(name);
                NSString	*aValue = GPGStringFromChars(aNotation->value);

                if([_notations objectForKey:aName] != nil)
                    NSLog(@"### We don't support more than one notation per name!! Ignoring notation '%@' with value '%@'", aName, aValue);
                else
                    [(NSMutableDictionary *)_notations setObject:aValue forKey:aName];
            }
            else
                [(NSMutableArray *)_policyURLs addObject:GPGStringFromChars(aNotation->value)];
            
            // FIXME Maybe GPGSignatureNotation should also copy attributes, and not keep reference to structure
            anObject = [[GPGSignatureNotation alloc] initWithInternalRepresentation:aNotation];
            [(NSMutableArray *)_signatureNotations addObject:anObject];
            [anObject release];
            
            aNotation = aNotation->next;
        }
        _algorithm = signature->pubkey_algo;
        _hashAlgorithm = signature->hash_algo;
        _signatureClass = 0; // Unsignificant value
    }

    return self;
}

- (id) initWithNewSignature:(gpgme_new_signature_t)signature
{
    if(self = [self init]){
        long	aValue;

        _fingerprint = [GPGStringFromChars(signature->fpr) retain];
        _validityError = GPGErrorNoError;
        _wrongKeyUsage = NO;
        aValue = signature->timestamp;
        if(aValue != 0L)
            _creationDate = [[NSCalendarDate dateWithTimeIntervalSince1970:aValue] retain];
        _validity = GPGValidityUltimate;
        _status = GPGErrorNoError;
        _summary = 0;
        _algorithm = signature->pubkey_algo;
        _hashAlgorithm = signature->hash_algo;
        _signatureClass = signature->sig_class;
        // We ignore gpgme_new_signature_t->type (GPGSignatureMode)
    }

    return self;
}

@end
