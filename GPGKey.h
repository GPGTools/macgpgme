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
    GPG_RSAAlgorithm                =  0,
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
 * Symmetric key algorithms
 * _{GPG_NoAlgorithm           Unencrypted data}
 * _{GPG_IDEAAlgorithm         [IDEA]}
 * _{GPG_TripleDESAlgorithm    [3DES] aka 3DES or DES-EDE - 168 bit key derived from 192}
 * _{GPG_CAST5Algorithm        [CAST5] 128 bit key}
 * _{GPG_BlowfishAlgorithm     [BLOWFISH] 128 bit key, 16 rounds}
 * _{GPG_SAFER_SK128Algorithm  13 rounds}
 * _{GPG_DES_SKAlgorithm       .}
 * _{GPG_AES128Algorithm       [AES] aka Rijndael}
 * _{GPG_AES192Algorithm       aka Rijndael 192}
 * _{GPG_AES256Algorithm       aka Rijndael 256}
 * _{GPG_TwoFishAlgorithm      [TWOFISH] twofish 256 bit}
 * _{GPG_SkipjackAlgorithm     Experimental: skipjack}
 * _{GPG_TwoFish_OldAlgorithm  Experimental: twofish 128 bit}
 * _{GPG_DummyAlgorithm        No encryption at all}
"*/
typedef enum {
    GPG_NoAlgorithm          =   0,
    GPG_IDEAAlgorithm        =   1,
    GPG_TripleDESAlgorithm   =   2,
    GPG_CAST5Algorithm       =   3,
    GPG_BlowfishAlgorithm    =   4,
    GPG_SAFER_SK128Algorithm =   5,
    GPG_DES_SKAlgorithm      =   6,
    GPG_AES128Algorithm      =   7,
    GPG_AES192Algorithm      =   8,
    GPG_AES256Algorithm      =   9,
    GPG_TwoFishAlgorithm     =  10,
    GPG_SkipjackAlgorithm    = 101,
    GPG_TwoFish_OldAlgorithm = 102,
    GPG_DummyAlgorithm       = 110
}GPGSymmetricKeyAlgorithm;


/*"
 * Hash algorithms
 * _{GPG_MD5HashAlgorithm             .}
 * _{GPG_SHA_1HashAlgorithm           [SHA1].}
 * _{GPG_RIPE_MD160HashAlgorithm      [RIPEMD160]}
 * _{GPG_DoubleWidthSHAHashAlgorithm  .}
 * _{GPG_MD2HashAlgorithm             .}
 * _{GPG_TIGER192HashAlgorithm        .}
 * _{GPG_HAVALHashAlgorithm           5 pass, 160 bit.}
"*/
typedef enum {
    GPG_MD5HashAlgorithm            = 1,
    GPG_SHA_1HashAlgorithm          = 2,
    GPG_RIPE_MD160HashAlgorithm     = 3,
    GPG_DoubleWidthSHAHashAlgorithm = 4,
    GPG_MD2HashAlgorithm            = 5,
    GPG_TIGER192HashAlgorithm       = 6,
    GPG_HAVALHashAlgorithm          = 7  // 5 pass, 160 bit
}GPGHashAlgorithm;


/*"
 * Compression algorithms
 * _{GPG_NoCompressionAlgorithm    No compression}
 * _{GPG_ZIPCompressionAlgorithm   [ZIP] Old zlib version (RFC1951) which is used by PGP}
 * _{GPG_ZLIBCompressionAlgorithm  [ZLIB] Default algorithm (RFC1950)}
"*/
typedef enum {
    GPG_NoCompressionAlgorithm   = 0,
    GPG_ZIPCompressionAlgorithm  = 1,
    GPG_ZLIBCompressionAlgorithm = 2
}GPGCompressionAlgorithm;


@interface GPGKey : GPGObject <NSCopying> /*"NSObject"*/
{
}

- (unsigned) hash;
- (BOOL) isEqual:(id)anObject;

/*"
 * Public and secret keys
"*/
- (GPGKey *) publicKey;
- (GPGKey *) secretKey;

/*"
 * Description
"*/
- (NSString *) descriptionAsXMLString;
- (NSDictionary *) dictionaryRepresentation;
+ (NSString *) algorithmDescription: (GPGPublicKeyAlgorithm)value;
+ (NSString *) validityDescription: (GPGValidity)value;
+ (NSString *) ownerTrustDescription: (GPGValidity)value;

/*"
 * Global key capabilities
"*/
- (BOOL) canEncrypt;
- (BOOL) canSign;
- (BOOL) canCertify;

/*"
 * Main key
"*/
- (NSString *) shortKeyID;
- (NSString *) keyID;
- (NSString *) fingerprint;
- (GPGPublicKeyAlgorithm) algorithm;
- (NSString *) algorithmDescription;
- (unsigned int) length;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;
- (BOOL) isKeyRevoked;
- (BOOL) isKeyInvalid;
- (BOOL) hasKeyExpired;
- (BOOL) isKeyDisabled;
- (BOOL) hasSecretPart;
- (BOOL) mainKeyCanEncrypt;
- (BOOL) mainKeyCanSign;
- (BOOL) mainKeyCanCertify;
- (GPGValidity) ownerTrust;
- (NSString *) ownerTrustDescription;
- (NSString *) issuerSerial;
- (NSString *) issuerName;
- (NSString *) chainID;

/*"
 * Sub keys
"*/
- (NSArray *) subkeysShortKeyIDs;
- (NSArray *) subkeysKeyIDs;
- (NSArray *) subkeysFingerprints;
- (NSArray *) subkeysAlgorithms;
- (NSArray *) subkeysAlgorithmDescriptions;
- (NSArray *) subkeysLengths;
- (NSArray *) subkeysCreationDates;
- (NSArray *) subkeysExpirationDates;
- (NSArray *) subkeysRevocationStatuses;
- (NSArray *) subkeysValidityStatuses;
- (NSArray *) subkeysExpirationStatuses;
- (NSArray *) subkeysActivityStatuses;
- (NSArray *) subkeysEncryptionCapabilities;
- (NSArray *) subkeysSigningCapabilities;
- (NSArray *) subkeysCertificationCapabilities;

/*"
 * Primary user ID
"*/
- (NSString *) userID;
- (NSString *) name;
- (NSString *) email;
- (NSString *) comment;
- (GPGValidity) validity;
- (NSString *) validityDescription;
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
- (NSArray *) validityDescriptions;
- (NSArray *) userIDsRevocationStatuses;
- (NSArray *) userIDsValidityStatuses;

// Not yet implemented in GPGME as of 0.3.8
// Don't work on them, there's no way to get this info
//- (unsigned int) type;

@end
