//
//  GPGKey.h
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

#import <GPGME/GPGObject.h>
#import <GPGME/GPGRecipients.h>


@class NSArray;
@class NSCalendarDate;
@class NSDictionary;
@class NSString;


// Algorithm numerical values (taken from OpenPGP, RFC2440)
// Public key algorithms
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

// Symetric key algorithms
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

// Hash algorithms
enum {
    GPG_MD5HashAlgorithm            = 1,
    GPG_SHA_1HashAlgorithm          = 2,
    GPG_RIPE_MD160HashAlgorithm     = 3,
    GPG_DoubleWidthSHAHashAlgorithm = 4,
    GPG_MD2HashAlgorithm            = 5,
    GPG_TIGER192HashAlgorithm       = 6,
    GPG_HAVALHashAlgorithm          = 7  // 5 pass, 160 bit
};


// You should never need to instantiate objects of that class.
// GPGContext does it for you.


@interface GPGKey : GPGObject
{
}

- (NSString *) xmlDescription;
// Can return nil if it is unable to make an XML description, for some reason
/*
<GnupgKeyblock>
  <mainkey>
    <secret/>
    <invalid/>
    <revoked/>
    <expired/>
    <disabled/>
    <keyid>aString</keyid>
    <fpr>aString</fpr>
    <algo>anUnsignedInt</algo>
    <len>anUnsignedInt</len>
    <created>aTime</created>
    <expires>aTime</expires> (not yet implemented)
  </mainkey>
  <userid> (first userid is the primary one)
    <invalid/>
    <revoked/>
    <raw>aString</raw>
    <name>aString</name>
    <email>aString</email>
    <comment>aString</comment>
  </userid>
  ... (other userids)
  <subkey>
    <secret/>
    <invalid/>
    <revoked/>
    <expired/>
    <disabled/>
    <keyid>aString</keyid>
    <fpr>aString</fpr>
    <algo>anUnsignedInt</algo>
    <len>anUnsignedInt</len>
    <created>aTime</created>
  </subkey>
</GnupgKeyblock>
 */
//- (NSDictionary *) dictionaryRepresentation;
// Uses the same keys as in XML representation, but places
// subkeys in an array keyed by "subkeys", and userIDs
// in an array keyed by "userids". Optional/boolean values are
// represented as NSNumbers. Time values are represented
// as NSCalendarDates

- (NSString *) keyID;
// Returns main key keyID
- (NSArray *) subkeysKeyIDs;
// Returns an array of NSString instances

- (NSString *) fingerprint;
// Returns main key fingerprint
- (NSArray *) subkeysFingerprints;
// Returns an array of NSString instances

- (unsigned int) algorithm;
// Returns main key algorithm
- (NSArray *) subkeysAlgorithms;
// Returns an array of NSNumber instances

- (unsigned int) length;
// Returns main key length
- (NSArray *) subkeysLengths;
// Returns an array of NSNumber instances

- (NSCalendarDate *) creationDate;
// Returns main key creation date
// Returns nil when not available or invalid
- (NSArray *) subkeysCreationDates;
// Returns an array of NSCalendarDate instances
// Array values can be +[NSValue:valueWithPointer:nil] when not available or invalid

// Not yet implemented
//- (NSCalendarDate *) expirationDate;
// Returns main key expiration date
//- (NSArray *) subkeysCreationDates;
// Returns an array of NSCalendarDate instances

//- (unsigned long) ownerTrust;

- (NSString *) userID;
// Returns primary userID
- (NSArray *) userIDs;
// Returns primary userID, followed by other userIDs

- (NSString *) name;
// Returns primary userID name
- (NSArray *) names;
// Returns primary userID name, followed by other userIDs names

- (NSString *) email;
// Returns primary userID email
- (NSArray *) emails;
// Returns primary userID email, followed by other userIDs emails

- (NSString *) comment;
// Returns primary userID comment
- (NSArray *) comments;
// Returns primary userID comment, followed by other userIDs comments

- (GPGValidity) validity;
// Returns primary userID validity
- (NSArray *) validities;
// Returns primary userID validity, followed by other userIDs validities

//- (unsigned int) type; Not yet implemented

- (BOOL) isKeyRevoked;
// Returns whether main key has been revoked
- (NSArray *) subkeysRevocationStatuses;
// Returns an array of NSNumber instances

- (BOOL) isKeyInvalid;
// Returns whether main key is invalid (e.g. due to a missing self-signature)
- (NSArray *) subkeysValidityStatuses;
// Returns an array of NSNumber instances

- (BOOL) hasKeyExpired;
// Returns whether main key has expired
- (NSArray *) subkeysExpirationStatuses;
// Returns an array of NSNumber instances

- (BOOL) isKeyDisabled;
// Returns whether main key is disabled
- (NSArray *) subkeysActivityStatuses;
// Returns an array of NSNumber instances

- (BOOL) isPrimaryUserIDRevoked;
// Returns whether primary userID has been revoked
- (NSArray *) userIDsRevocationStatuses;
// Returns an array of NSNumber instances
// First value is for primary userID

- (BOOL) isPrimaryUserIDInvalid;
// Returns whether primary userID is invalid
- (NSArray *) userIDsValidityStatuses;
// Returns an array of NSNumber instances
// First value is for primary userID

- (BOOL) hasSecretPart;

- (BOOL) canEncrypt;
// Returns global encryption capability of the key
- (BOOL) mainKeyCanEncrypt;
// Returns whether main key can be used for encyption
- (NSArray *) subkeysEncryptionCapabilities;
// Returns an array of NSNumber instances

- (BOOL) canSign;
// Returns global signature capability of the key
- (BOOL) mainKeyCanSign;
// Returns whether main key can be used for signing
- (NSArray *) subkeysSigningCapabilities;
// Returns an array of NSNumber instances

- (BOOL) canCertify;
// Returns global certification capability of the key
- (BOOL) mainKeyCanCertify;
// Returns whether main key can be used for certification
- (NSArray *) subkeysCertificationCapabilities;
// Returns an array of NSNumber instances

@end
