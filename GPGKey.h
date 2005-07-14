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
#include <MacGPGME/GPGKeyDefines.h>

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
