//
//  GPGKey.h
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
#import <GPGME/GPGRecipients.h>


@class NSArray;
@class NSCalendarDate;
@class NSDictionary;
@class NSEnumerator;
@class NSString;


/*"
 * Algorithm numerical values (taken from OpenPGP, RFC2440)
"*/
/*"
 * Public key algorithms
"*/
enum {
    GPG_RSAAlgorithm                = 1,  // Encrypt or Sign
    GPG_RSAEncryptOnlyAlgorithm     = 2,  // aka RSA-E
    GPG_RSASignOnlyAlgorithm        = 3,  // aka RSA-S
    GPG_ElgamalEncryptOnlyAlgorithm = 16, // aka Elgamal-E
    GPG_DSAAlgorithm                = 17, // Digital Signature Standard
    GPG_EllipticCurveAlgorithm      = 18,
    GPG_ECDSAAlgorithm              = 19,
    GPG_ElgamalAlgorithm            = 20,
    GPG_DiffieHellmanAlgorithm      = 21  // Encrypt or Sign
};

/*"
 * Symetric key algorithms
"*/
enum {
    GPG_NoAlgorithm          = 0,   // Unencrypted data
    GPG_IDEAAlgorithm        = 1,
    GPG_TripleDESAlgorithm   = 2,   // aka 3DES or DES-EDE - 168 bit key derived from 192
    GPG_CAST5Algorithm       = 3,   // 128 bit key
    GPG_BlowfishAlgorithm    = 4,   // 128 bit key, 16 rounds
    GPG_SAFER_SK128Algorithm = 5,   // 13 rounds
    GPG_DES_SKAlgorithm      = 6,
    GPG_AES128Algorithm      = 7,   // aka Rijndael
    GPG_AES192Algorithm      = 8,   // aka Rijndael 192
    GPG_AES256Algorithm      = 9,   // aka Rijndael 256
    GPG_TwoFishAlgorithm     = 10,  // twofish 256 bit
    GPG_SkipjackAlgorithm    = 101, // Experimental: skipjack
    GPG_TwoFish_OldAlgorithm = 102, // Experimental: twofish 128 bit
    GPG_DummyAlgorithm       = 110  // No encryption at all
};

/*"
 * Hash algorithms
"*/
enum {
    GPG_MD5HashAlgorithm            = 1,
    GPG_SHA_1HashAlgorithm          = 2,
    GPG_RIPE_MD160HashAlgorithm     = 3,
    GPG_DoubleWidthSHAHashAlgorithm = 4,
    GPG_MD2HashAlgorithm            = 5,
    GPG_TIGER192HashAlgorithm       = 6,
    GPG_HAVALHashAlgorithm          = 7  // 5 pass, 160 bit
};


@interface GPGKey : GPGObject
{
}

- (NSString *) xmlDescription;
- (NSDictionary *) dictionaryRepresentation;
// Uses the same keys as in XML representation, but places
// subkeys in an array keyed by "subkeys", and userIDs
// in an array keyed by "userids". Optional/boolean values are
// represented as NSNumbers. Time values are represented
// as NSCalendarDates

- (NSString *) keyID;
- (NSArray *) subkeysKeyIDs;

- (NSString *) fingerprint;
- (NSArray *) subkeysFingerprints;

- (unsigned int) algorithm;
- (NSArray *) subkeysAlgorithms;

- (unsigned int) length;
- (NSArray *) subkeysLengths;

- (NSCalendarDate *) creationDate;
- (NSArray *) subkeysCreationDates;

// not yet implimented in GPGME as of 0.2.2
// don't work on them, there's no way to get this info
//- (NSCalendarDate *) expirationDate;
//- (NSArray *) subkeysExpirationDates;

// not yet implimented in GPGME as of 0.2.2
// don't work on them, there's no way to get this info
//- (unsigned long) ownerTrust;

- (NSString *) userID;
- (NSArray *) userIDs;

- (NSString *) name;
- (NSArray *) names;

- (NSString *) email;
- (NSArray *) emails;

- (NSString *) comment;
- (NSArray *) comments;

- (GPGValidity) validity;
- (NSArray *) validities;

// not yet implimented in GPGME as of 0.2.2
// don't work on them, there's no way to get this info
//- (unsigned int) type;

- (BOOL) isKeyRevoked;
- (NSArray *) subkeysRevocationStatuses;

- (BOOL) isKeyInvalid;
- (NSArray *) subkeysValidityStatuses;

- (BOOL) hasKeyExpired;
- (NSArray *) subkeysExpirationStatuses;

- (BOOL) isKeyDisabled;
- (NSArray *) subkeysActivityStatuses;

- (BOOL) isPrimaryUserIDRevoked;
- (NSArray *) userIDsRevocationStatuses;

- (BOOL) isPrimaryUserIDInvalid;
- (NSArray *) userIDsValidityStatuses;

- (BOOL) hasSecretPart;
- (NSArray *) subkeysSecretnessStatuses;

- (BOOL) canEncrypt;
- (BOOL) mainKeyCanEncrypt;
- (NSArray *) subkeysEncryptionCapabilities;

- (BOOL) canSign;
- (BOOL) mainKeyCanSign;
- (NSArray *) subkeysSigningCapabilities;

- (BOOL) canCertify;
- (BOOL) mainKeyCanCertify;
- (NSArray *) subkeysCertificationCapabilities;

@end
