//
//  GPGKey.h
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
 * _{GPG_RSAAlgorithm                 Encrypt or Sign.}
 * _{GPG_RSAEncryptOnlyAlgorithm      aka RSA-E.}
 * _{GPG_RSASignOnlyAlgorithm         aka RSA-S.}
 * _{GPG_ElgamalEncryptOnlyAlgorithm  aka Elgamal-E.}
 * _{GPG_DSAAlgorithm                 Digital Signature Standard.}
 * _{GPG_EllipticCurveAlgorithm       .}
 * _{GPG_ECDSAAlgorithm               .}
 * _{GPG_ElgamalAlgorithm             .}
 * _{GPG_DiffieHellmanAlgorithm       Encrypt or Sign.}
"*/
typedef enum {
    GPG_RSAAlgorithm                =  1,
    GPG_RSAEncryptOnlyAlgorithm     =  2,
    GPG_RSASignOnlyAlgorithm        =  3,
    GPG_ElgamalEncryptOnlyAlgorithm = 16,
    GPG_DSAAlgorithm                = 17,
    GPG_EllipticCurveAlgorithm      = 18,
    GPG_ECDSAAlgorithm              = 19,
    GPG_ElgamalAlgorithm            = 20,
    GPG_DiffieHellmanAlgorithm      = 21
}GPGPublicKeyAlgorithm;

/*"
 * Symetric key algorithms
"*/
enum {
    GPG_NoAlgorithm          =   0, // Unencrypted data
    GPG_IDEAAlgorithm        =   1,
    GPG_TripleDESAlgorithm   =   2, // aka 3DES or DES-EDE - 168 bit key derived from 192
    GPG_CAST5Algorithm       =   3, // 128 bit key
    GPG_BlowfishAlgorithm    =   4, // 128 bit key, 16 rounds
    GPG_SAFER_SK128Algorithm =   5, // 13 rounds
    GPG_DES_SKAlgorithm      =   6,
    GPG_AES128Algorithm      =   7, // aka Rijndael
    GPG_AES192Algorithm      =   8, // aka Rijndael 192
    GPG_AES256Algorithm      =   9, // aka Rijndael 256
    GPG_TwoFishAlgorithm     =  10, // twofish 256 bit
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


@interface GPGKey : GPGObject <NSCopying> /*"NSObject"*/
{
}

- (unsigned) hash;
- (BOOL) isEqual:(id)anObject;

/*"
 * Description
"*/
- (NSString *) descriptionAsXMLString;
- (NSDictionary *) dictionaryRepresentation;

/*"
 * Global key capabilities
"*/
- (BOOL) canEncrypt;
- (BOOL) canSign;
- (BOOL) canCertify;

/*"
 * Main key
"*/
- (NSString *) keyID;
- (NSString *) fingerprint;
- (GPGPublicKeyAlgorithm) algorithm;
- (unsigned int) length;
- (NSCalendarDate *) creationDate;
- (BOOL) isKeyRevoked;
- (BOOL) isKeyInvalid;
- (BOOL) hasKeyExpired;
- (BOOL) isKeyDisabled;
- (BOOL) hasSecretPart;
- (BOOL) mainKeyCanEncrypt;
- (BOOL) mainKeyCanSign;
- (BOOL) mainKeyCanCertify;

/*"
 * Sub keys
"*/
- (NSArray *) subkeysKeyIDs;
- (NSArray *) subkeysFingerprints;
- (NSArray *) subkeysAlgorithms;
- (NSArray *) subkeysLengths;
- (NSArray *) subkeysCreationDates;
- (NSArray *) subkeysRevocationStatuses;
- (NSArray *) subkeysValidityStatuses;
- (NSArray *) subkeysExpirationStatuses;
- (NSArray *) subkeysActivityStatuses;
- (NSArray *) subkeysEncryptionCapabilities;
- (NSArray *) subkeysSigningCapabilities;
- (NSArray *) subkeysCertificationCapabilities;

// Not yet implemented in GPGME as of 0.3.0
// Don't work on them, there's no way to get this info
//- (NSCalendarDate *) expirationDate;
//- (NSArray *) subkeysExpirationDates;

// Not yet implemented in GPGME as of 0.3.0
// Don't work on them, there's no way to get this info
//- (unsigned long) ownerTrust;

/*"
 * Primary user ID
"*/
- (NSString *) userID;
- (NSString *) name;
- (NSString *) email;
- (NSString *) comment;
- (GPGValidity) validity;
- (BOOL) isPrimaryUserIDRevoked;
- (BOOL) isPrimaryUserIDInvalid;

/*"
 * All user IDs
"*/
- (NSArray *) userIDs;
- (NSArray *) names;
- (NSArray *) emails;
- (NSArray *) comments;
- (NSArray *) validities;
- (NSArray *) userIDsRevocationStatuses;
- (NSArray *) userIDsValidityStatuses;


// Not yet implemented in GPGME as of 0.3.0
// Don't work on them, there's no way to get this info
//- (unsigned int) type;

@end
