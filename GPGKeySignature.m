//
//  GPGKeySignature.m
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Thu Dec 26 2002.
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

#include <MacGPGME/GPGKeySignature.h>
#include <MacGPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


@implementation GPGKeySignature
/*"
 * %{Key signatures} are one component of a #GPGKey object, and validate user
 * IDs on the key.
 *
 * The signatures on a key are only available if the key was retrieved via a
 * listing operation with the #GPGKeyListModeSignatures mode enabled, because
 * it is expensive to retrieve all signatures of a key.
 *
 * #GPGKeySignature instances are returned by #{-[GPGUserID signatures]};
 * you should never need to instantiate yourself objects of that class. It is
 * guaranteed that the owning GPGUserID instance will never be deallocated
 * before the GPGKeySignature has been deallocated, without creating
 * non-breakable retain-cycles.
 *
 * An instance represents a signature on a %{user ID} of a %key.
 *
 * Key signatures raise a NSInternalInconsistencyException when methods
 * -fingerprint, -summary, -notations, -policyURLs, -validity, -validityError, 
 * -wrongKeyUsage, -validityDescription, -hashAlgorithm,
 * -hashAlgorithmDescription are invoked.
"*/

- (id) retain
{
    // See GPGKey.m for more information
    [_signedUserID retain];
    _refCount++;

    return self;
}

- (oneway void) release
{
    // See GPGKey.m for more information
    if(_refCount > 0){
        _refCount--;
        [_signedUserID release];
    }
    else{
        if(_refCount < 0)
            NSLog(@"### GPGKeySignature: _refCount < 0! (%d)", _refCount);
        [super release];
    }
}

- (void) dealloc
{
	[_signerKeyID release];
    [_userID release];
    [_name release];
    [_email release];
    [_comment release];
    
	[super dealloc];
}

- (NSString *) fingerprint
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have fingerprint."];
    
    return nil;
}

- (GPGSignatureSummaryMask) summary
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have summary."];
    
    return 0;
}

- (NSDictionary *) notations
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have notations."];
    
    return nil;
}

- (NSArray *) policyURLs
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have policy URLs."];

    return nil;
}

- (GPGValidity) validity
{
#warning Ask Werner whether it is not _yet_ available
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have validity."];
    
    return 0;
}

- (NSString *) validityDescription
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have validityDescription."];
    
    return nil;
}

- (GPGError) validityError
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have validityError."];

    return -1;
}

- (BOOL) wrongKeyUsage
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have wrongKeyUsage."];

    return NO;
}

- (GPGHashAlgorithm) hashAlgorithm
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have hashAlgorithm."];

    return 0;
}

- (NSString *) hashAlgorithmDescription
{
    [NSException raise:NSInternalInconsistencyException format:@"GPGKeySignature instances don't have hashAlgorithmDescription."];

    return nil;
}

- (NSString *) signerKeyID
/*"
 * Returns the %{key ID} of the signer's %key.
"*/
{
    return _signerKeyID;
}

- (NSString *) userID
/*"
 * Returns the main %{user ID} of the signer's %key.
"*/
{
    return _userID;
}

- (NSString *) name
/*"
 * Returns the name on the signer's %key, if available. Taken from the main
 * %{user ID} of the signer's %key.
"*/
{
    return _name;
}

- (NSString *) email
/*"
 * Returns the email address on the signer's %key, if available. Taken from
 * the main %{user ID} of the signer's %key.
"*/
{
    return _email;
}

- (NSString *) comment
/*"
 * Returns the comment on the signer's %key, if available. Taken from the main
 * %{user ID} of the signer's %key.
"*/
{
    return _comment;
}

- (NSCalendarDate *) creationDate
/*"
 * Returns %{signature} creation date. Returns nil when not available or
 * invalid.
"*/
{
    return _creationDate;
}

- (NSCalendarDate *) expirationDate
/*"
 * Returns %{signature} expiration date. Returns nil when not available or
 * invalid.
"*/
{
    return _expirationDate;
}

- (BOOL) isRevocationSignature
/*"
 * Returns whether the signature is a revocation signature or not.
"*/
{
    return _isRevocationSignature;
}

- (BOOL) hasSignatureExpired
/*"
 * Returns whether %{signature} has expired or not.
"*/
{
    return _hasSignatureExpired;
}

- (BOOL) isSignatureInvalid
/*"
 * Returns whether %{signature} is invalid or not.
"*/
{
    return _isSignatureInvalid;
}

- (BOOL) isExportable
/*"
 * Returns whether %{signature} is exportable or not (locally signed).
"*/
{
    return _isExportable;
}

- (GPGError) status
/*"
 * Returns %signature status.
 *
 * In particular, the following status codes are of interest:
 * _{GPGErrorNoError           This status indicates that the signature is
 *                             valid.}
 * _{GPGErrorSignatureExpired  This status indicates that the signature is
 *                             valid but expired.}
 * _{GPGErrorKeyExpired        This status indicates that the signature is
 *                             valid but the key used to verify the
 *                             signature has expired.}
 * _{GPGErrorBadSignature      This status indicates that the signature is
 *                             invalid.}
 * _{GPGErrorNoPublicKey       This status indicates that the signature could
 *                             not be verified due to a missing key.}
 * _{GPGErrorGeneralError      This status indicates that there was some other
 *                             error which prevented the signature
 *                             verification.}
"*/
{
    return _status;
}

- (GPGUserID *) signedUserID
/*"
 * Returns the #GPGUserID signed by this signature.
"*/
{
    return _signedUserID;
}

@end

@implementation GPGKeySignature(GPGInternals)

- (id) initWithKeySignature:(gpgme_key_sig_t)keySignature userID:(GPGUserID *)userID
{
    if(self = [self init]){
        long	aValue;

        _signerKeyID = [GPGStringFromChars(keySignature->keyid) retain];
        _algorithm = keySignature->pubkey_algo;
        _userID = [GPGStringFromChars(keySignature->uid) retain];
        _name = [GPGStringFromChars(keySignature->name) retain];
        _email = [GPGStringFromChars(keySignature->email) retain];
        _comment = [GPGStringFromChars(keySignature->comment) retain];
        aValue = keySignature->timestamp;
        if(aValue > 0)
            _creationDate = [[NSCalendarDate dateWithTimeIntervalSince1970:aValue] retain];
        aValue = keySignature->expires;
        if(aValue > 0)
            _expirationDate = [[NSCalendarDate dateWithTimeIntervalSince1970:aValue] retain];
        _isRevocationSignature = !!keySignature->revoked;
        _hasSignatureExpired = !!keySignature->expired;
        _isSignatureInvalid = !!keySignature->invalid;
        _isExportable = !!keySignature->exportable;
        _signatureClass = keySignature->sig_class;
        _status = keySignature->status;
        _signedUserID = userID; // Not retained; backpointer
        _hashAlgorithm = 0; // Unsignificant value (GPG_NoHashAlgorithm)
    }
    
    return self;
}

@end
