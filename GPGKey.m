//
//  GPGKey.m
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

#import "GPGKey.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _key	((GpgmeKey)_internalRepresentation)


@implementation GPGKey

- (void) dealloc
{
    GpgmeKey	cachedKey = _key;
    
    [super dealloc];

    gpgme_key_unref(cachedKey); // It will call gpgme_key_release() if necessary
}

- (NSString *) xmlDescription
{
    char		*aBuffer = gpgme_key_get_as_xml(_key);
    NSString	*aString = nil;

    if(aBuffer != NULL){
        aString = [NSString stringWithUTF8String:aBuffer];
        free(aBuffer);
    }
    
    return aString;
}

- (NSString *) mainStringAttributeWithIdentifier:(GpgmeAttr)identifier
{
    const char	*aCString = gpgme_key_get_string_attr(_key, identifier, NULL, 0);

    if(aCString != NULL)
        return [NSString stringWithUTF8String:aCString];
    else
        return nil;
}

- (NSMutableArray *) subStringAttributesWithIdentifier:(GpgmeAttr)identifier maxCount:(unsigned)maxCount
{
    // If maxCount == 0, we stop enumerating when we get a NULL value,
    // else we replace NULL values with empty strings, and continue
    // up to maxCount. This is a workaround for the missing functions
    // gpgme_key_subkeys_count() and gpgme_key_userids_count()...
    int				i = 1;
    const char		*aCString;
    NSMutableArray	*attributes = [NSMutableArray array];

    do{
        aCString = gpgme_key_get_string_attr(_key, identifier, NULL, i++);
        if(aCString == NULL)
            if(maxCount > 0)
                [attributes addObject:@""];
            else
                break;
        else
            [attributes addObject:[NSString stringWithUTF8String:aCString]];
    }while(maxCount == 0 || i <= maxCount);

    return attributes;
}

- (unsigned) subkeysCount
{
    return [[self subkeysKeyIDs] count];
}

- (unsigned) secondaryUserIDsCount
{
    return [[self subStringAttributesWithIdentifier:GPGME_ATTR_USERID maxCount:0] count];
}

- (NSString *) keyID
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_KEYID];
}

- (NSArray *) subkeysKeyIDs
{
    return [self subStringAttributesWithIdentifier:GPGME_ATTR_KEYID maxCount:0];
}

- (NSString *) fingerprint
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_FPR];
}

- (NSArray *) subkeysFingerprints
{
#warning BUG: no fingerprint for subkeys!
    return [self subStringAttributesWithIdentifier:GPGME_ATTR_FPR maxCount:[self subkeysCount]];
}

- (unsigned int) algorithm
{
    return (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_ALGO, NULL, 0);
}

- (NSArray *) subkeysAlgorithms
{
    int				i = 1;
    unsigned int	aValue, maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_ALGO, NULL, i);
        [attributes addObject:[NSNumber numberWithUnsignedInt:aValue]];
    }

    return attributes;
}

- (unsigned int) length
{
    return (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_LEN, NULL, 0);
}

- (NSArray *) subkeysLengths
{
    int				i = 1;
    unsigned int	aValue, maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_LEN, NULL, i);
        [attributes addObject:[NSNumber numberWithUnsignedInt:aValue]];
    }

    return attributes;
}

- (NSCalendarDate *) creationDate
{
    unsigned long	aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CREATED, NULL, 0);

    if(aValue == 0L)
        return nil;
    else
        return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}

- (NSArray *) subkeysCreationDates
{
    int				i = 1;
    unsigned long	aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CREATED, NULL, i);
        if(aValue == 0L)
            [attributes addObject:[NSValue valueWithPointer:nil]];
        else
            [attributes addObject:[NSCalendarDate dateWithTimeIntervalSince1970:aValue]];
    }

    return attributes;
}

- (NSString *) userID
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_USERID];
}

- (NSArray *) userIDs
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_USERID maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) name
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_NAME];
}

- (NSArray *) names
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_NAME maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) email
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_EMAIL];
}

- (NSArray *) emails
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_EMAIL maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) comment
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_COMMENT];
}

- (NSArray *) comments
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_COMMENT maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (GPGValidity) validity
{
    return gpgme_key_get_ulong_attr(_key, GPGME_ATTR_VALIDITY, NULL, 0);
}

- (NSArray *) validities
{
    int				i = 0;
    GPGValidity		aValue;
    unsigned		maxCount = [self secondaryUserIDsCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 0; i <= maxCount; i++){
        aValue = (GPGValidity)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_VALIDITY, NULL, i);
        [attributes addObject:[NSNumber numberWithInt:aValue]];
    }

    return attributes;
}

- (BOOL) isKeyRevoked
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_REVOKED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysRevocationStatuses
{
    int				i = 1;
    BOOL			aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_REVOKED, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:aValue]];
    }
    
    return attributes;
}

- (BOOL) isKeyInvalid
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_INVALID, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysValidityStatuses
{
    int				i = 1;
    BOOL			aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_INVALID, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:aValue]];
    }

    return attributes;
}

- (BOOL) hasKeyExpired
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_EXPIRED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysExpirationStatuses
{
    int				i = 1;
    BOOL			aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_EXPIRED, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:aValue]];
    }

    return attributes;
}

- (BOOL) isKeyDisabled
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_DISABLED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysActivityStatuses
{
    int				i = 1;
    BOOL			aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_DISABLED, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:aValue]];
    }
    
    return attributes;
}

- (BOOL) isPrimaryUserIDRevoked
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_REVOKED, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsRevocationStatuses
{
    int				i = 0;
    BOOL			aValue;
    unsigned		maxCount = [self secondaryUserIDsCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 0; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_REVOKED, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:aValue]];
    }

    return attributes;
}

- (BOOL) isPrimaryUserIDInvalid
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_INVALID, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsValidityStatuses
{
    int				i = 0;
    unsigned long	aValue;
    unsigned		maxCount = [self secondaryUserIDsCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 0; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_INVALID, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:!!aValue]];
    }

    return attributes;
}

- (BOOL) hasSecretPart
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_IS_SECRET, NULL, 0);

    return (!!result);
}
#warning We miss a function to get hasSecretPart from subkeys...

- (BOOL) canEncrypt
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_ENCRYPT, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanEncrypt
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 'e') != NULL;
}

- (NSArray *) subkeysEncryptionCapabilities
{
    int				i = 1;
    const char		*aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:(strchr(aValue, 'e') != NULL)]];
    }

    return attributes;
}

- (BOOL) canSign
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_SIGN, NULL, 0);

    return (result != 0);
}

- (BOOL) mainKeyCanSign
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 's') != NULL;
}

- (NSArray *) subkeysSigningCapabilities
{
    int				i = 1;
    const char		*aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:(strchr(aValue, 's') != NULL)]];
    }

    return attributes;
}

- (BOOL) canCertify
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_CERTIFY, NULL, 0);

    return (result != 0);
}

- (BOOL) mainKeyCanCertify
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 'c') != NULL;
}

- (NSArray *) subkeysCertificationCapabilities
{
    int				i = 1;
    const char		*aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, i);
        [attributes addObject:[NSNumber numberWithBool:(strchr(aValue, 'c') != NULL)]];
    }
    
    return attributes;
}

@end


@implementation GPGKey(GPGInternals)

- (id) initWithInternalRepresentation:(void *)aPtr
{
    id	originalSelf = self;

    if(self = [super initWithInternalRepresentation:aPtr]){
        if(originalSelf == self)
            gpgme_key_ref(_key);
    }

    return self;
}

- (GpgmeKey) gpgmeKey
{
    return _key;
}

@end
