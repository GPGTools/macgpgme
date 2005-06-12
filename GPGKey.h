//
//  GPGKey.h
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

#ifndef GPGKEY_H
#define GPGKEY_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGEngine.h>
#include <MacGPGME/GPGContext.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSArray;
@class NSCalendarDate;
@class NSData;
@class NSDictionary;
@class NSEnumerator;
@class NSString;


/*"
 * The #GPGValidity type is used to specify the validity of a %{user ID} in a
 * key, or for a #GPGTrustItem instance. The following validities are defined:
 * _{GPGValidityUnknown    The %{user ID} is of unknown validity [?].}
 * _{GPGValidityUndefined  No value assigned. The validity of the %{user ID}
 *                         is undefined [q].}
 * _{GPGValidityNever      The %{user ID} is never valid [n].}
 * _{GPGValidityMarginal   The %{user ID} is marginally valid [m].}
 * _{GPGValidityFull       The %{user ID} is fully valid [f].}
 * _{GPGValidityUltimate   The %{user ID} is ultimately valid [u]. Only used
 *                         for keys for which the secret key is also
 *                         available.}
 *
 * Don't assume that higher value means higher validity; this might change in the future.
"*/
typedef enum {
    GPGValidityUnknown   = 0,
    GPGValidityUndefined = 1,
    GPGValidityNever     = 2,
    GPGValidityMarginal  = 3,
    GPGValidityFull      = 4,
    GPGValidityUltimate  = 5
} GPGValidity;


/*"
 * Algorithm numerical values (taken from OpenPGP, RFC2440)
"*/
/*"
 * Public key algorithms are used for encryption, decryption, signing and
 * verification of signatures. You can convert the numerical values to strings
 * with #{GPGPublicKeyAlgorithmDescription()} and
 * #{GPGLocalizedPublicKeyAlgorithmDescription()} for printing.
 * _{GPG_RSAAlgorithm                 RSA (Rivest, Shamir, Adleman) algorithm.}
 * _{GPG_RSAEncryptOnlyAlgorithm      %Deprecated.
 *                                    RSA (Rivest, Shamir, Adleman) algorithm
 *                                    for encryption and decryption only
 *                                    (aka RSA-E).}
 * _{GPG_RSASignOnlyAlgorithm         %Deprecated.
 *                                    RSA (Rivest, Shamir, Adleman) algorithm
 *                                    for signing and verification only
 *                                    (aka RSA-S).}
 * _{GPG_ElgamalEncryptOnlyAlgorithm  Elgamal (aka Elgamal-E);
 *                                    used specifically in GnuPG.}
 * _{GPG_DSAAlgorithm                 Digital Signature Algorithm.}
 * _{GPG_EllipticCurveAlgorithm       .}
 * _{GPG_ECDSAAlgorithm               .}
 * _{GPG_ElgamalAlgorithm             Elgamal.}
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
 * _{GPG_NoHashAlgorithm              .}
 * _{GPG_MD5HashAlgorithm             .}
 * _{GPG_SHA_1HashAlgorithm           [SHA1].}
 * _{GPG_RIPE_MD160HashAlgorithm      [RIPEMD160]}
 * _{GPG_DoubleWidthSHAHashAlgorithm  .}
 * _{GPG_MD2HashAlgorithm             .}
 * _{GPG_TIGER192HashAlgorithm        .}
 * _{GPG_HAVALHashAlgorithm           5 pass, 160 bit.}
 * _{GPG_SHA256HashAlgorithm          .}
 * _{GPG_SHA384HashAlgorithm          .}
 * _{GPG_SHA512HashAlgorithm          .}
 * _{GPG_MD4HashAlgorithm             .}
 * _{GPG_CRC32HashAlgorithm           .}
 * _{GPG_CRC32RFC1510HashAlgorithm    .}
 * _{GPG_CRC32RFC2440HashAlgorithm    .}
"*/
typedef enum {
    GPG_NoHashAlgorithm             =   0,
    GPG_MD5HashAlgorithm            =   1,
    GPG_SHA_1HashAlgorithm          =   2,
    GPG_RIPE_MD160HashAlgorithm     =   3,
    GPG_DoubleWidthSHAHashAlgorithm =   4,
    GPG_MD2HashAlgorithm            =   5,
    GPG_TIGER192HashAlgorithm       =   6,
    GPG_HAVALHashAlgorithm          =   7,
    GPG_SHA256HashAlgorithm         =   8,
    GPG_SHA384HashAlgorithm         =   9,
    GPG_SHA512HashAlgorithm         =  10,
    GPG_MD4HashAlgorithm            = 301,
    GPG_CRC32HashAlgorithm          = 302,
    GPG_CRC32RFC1510HashAlgorithm   = 303,
    GPG_CRC24RFC2440HashAlgorithm   = 304,
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
    NSArray	*_subkeys; /*"Array containing GPGSubkey instances"*/
    NSArray	*_userIDs; /*"Array containing GPGUserID instances"*/
    NSData	*_photoData;
    BOOL	_checkedPhotoData;
}

- (unsigned) hash;
- (BOOL) isEqual:(id)anObject;
+ (NSString *) formattedFingerprint:(NSString *)fingerprint;

/*"
 * Public and secret keys
"*/
- (GPGKey *) publicKey;
- (GPGKey *) secretKey;

/*"
 * Description
"*/
- (NSDictionary *) dictionaryRepresentation;

/*"
 * Global key capabilities
"*/
- (BOOL) canEncrypt;
- (BOOL) canSign;
- (BOOL) canCertify;
- (BOOL) canAuthenticate;

/*"
 * Main key
"*/
- (NSString *) shortKeyID;
- (NSString *) keyID;
- (NSString *) fingerprint;
- (NSString *) formattedFingerprint;
- (GPGPublicKeyAlgorithm) algorithm;
- (NSString *) algorithmDescription;
- (unsigned int) length;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;
- (BOOL) isKeyRevoked;
- (BOOL) isKeyInvalid;
- (BOOL) hasKeyExpired;
- (BOOL) isKeyDisabled;
- (BOOL) isSecret;
- (GPGValidity) ownerTrust;
- (NSString *) ownerTrustDescription;
- (NSString *) issuerSerial;
- (NSString *) issuerName;
- (NSString *) chainID;

/*"
 * All subkeys
"*/
- (NSArray *) subkeys;

/*"
 * Primary user ID information
"*/
- (NSString *) userID;
- (NSString *) name;
- (NSString *) email;
- (NSString *) comment;
- (GPGValidity) validity;
- (NSString *) validityDescription;

/*"
 * All user IDs
"*/
- (NSArray *) userIDs;

/*"
 * Supported protocol
"*/
- (GPGProtocol) supportedProtocol;
- (NSString *) supportedProtocolDescription;

/*"
 * Other key attributes
"*/
- (NSData *) photoData;
- (GPGKeyListMode) keyListMode;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGKEY_H */
