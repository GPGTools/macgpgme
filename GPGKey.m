//
//  GPGKey.m
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

#import "GPGKey.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _key	((GpgmeKey)_internalRepresentation)


@implementation GPGKey
/*"
 * You should never need to instantiate objects of that class. #GPGContext does
 * it for you.
"*/

- (void) dealloc
{
    GpgmeKey	cachedKey = _key;
    
    [super dealloc];

    gpgme_key_unref(cachedKey); // It will call gpgme_key_release() if necessary
}

- (NSString *) xmlDescription
/*"
 * Can return nil if it is unable to make an XML description, for some reason.
 * 
 * !{<GnupgKeyblock>
 *   <mainkey>
 *     <secret/>
 *     <invalid/>
 *     <revoked/>
 *     <expired/>
 *     <disabled/>
 *     <keyid>aString</keyid>
 *     <fpr>aString</fpr>
 *     <algo>anUnsignedInt</algo>
 *     <len>anUnsignedInt</len>
 *     <created>aTime</created>
 *     <expires>aTime</expires> (not yet implemented)
 *   </mainkey>
 *   <userid> (first userid is the primary one)
 *     <invalid/>
 *     <revoked/>
 *     <raw>aString</raw>
 *     <name>aString</name>
 *     <email>aString</email>
 *     <comment>aString</comment>
 *   </userid>
 *   ... (other userids)
 *   <subkey>
 *     <secret/>
 *     <invalid/>
 *     <revoked/>
 *     <expired/>
 *     <disabled/>
 *     <keyid>aString</keyid>
 *     <fpr>aString</fpr>
 *     <algo>anUnsignedInt</algo>
 *     <len>anUnsignedInt</len>
 *     <created>aTime</created>
 *   </subkey>
 * </GnupgKeyblock>}
"*/
{
    char		*aBuffer = gpgme_key_get_as_xml(_key);
    NSString	*aString = nil;

    if(aBuffer != NULL){
        aString = [NSString stringWithUTF8String:aBuffer];
        free(aBuffer);
    }
    
    return aString;
}

- (NSDictionary *) dictionaryRepresentation
// Uses the same keys as in XML representation, but places
// subkeys in an array keyed by "subkeys", and userIDs
// in an array keyed by "userids". Optional/boolean values are
// represented as NSNumbers. Time values are represented
// as NSCalendarDates
{
    NSMutableDictionary *key_dict = [[NSMutableDictionary alloc] init];
    NSArray *uids, *uids_names, *uids_emails, *uids_validities,
            *subkeys;
    
    //these should be pointers!!!
    [key_dict setObject: [self hasSecretPart] forKey:"@secret"];
    [key_dict setObject: [self isKeyInvalid] forKey:"@invalid"];
    [key_dict setObject: [self isKeyRevoked] forKey:"@revoked"];
    [key_dict setObject: [self hasKeyExpired] forKey:"@expired"];
    [key_dict setObject: [self isKeyDisabled] forKey:"@disabled"];
    [key_dict setObject: [self keyID] forKey: @"keyid"];
    [key_dict setObject: [self fingerprint] forKey:"@fpr"];
    [key_dict setObject: [self algorithm] forKey:"@algo"];
    [key_dict setObject: [self length] forKey:"@len"];
    [key_dict setObject: [self creationDate] forKey:"@created"];
    //expired not yet implimented in GPGME 0.2.2; but Werner about it ;-)
    //todo:  subkeys and userids
    [key_dict setObject: [[NSMutableArray alloc] init] forKey:"@userids"];
    uids = [[NSArray alloc] initWithArray: [self userIDs]];
    /*for (i = 0; i < [uids count]; i++)	{
        
    }*/
    subkeys = [[NSArray alloc] initWithArray: [self subkeysKeyIDs]];
    [key_dict setObject: [[NSMutableArray alloc] init] forKey:"@subkeys"];
    //can mutablearrays/dictionaries be edited in place in a dictionary?
    
    return [[NSDictionary alloc] initWithDictionary: key_dict copyItems: YES];
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
/*"
 * Returns main key keyID.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_KEYID];
}

- (NSArray *) subkeysKeyIDs
/*"
 * Returns an array of #NSString instances.
"*/
{
    return [self subStringAttributesWithIdentifier:GPGME_ATTR_KEYID maxCount:0];
}

- (NSString *) fingerprint
/*"
 * Returns main key fingerprint.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_FPR];
}

- (NSArray *) subkeysFingerprints
/*"
 * Returns an array of #NSString instances.
"*/
{
#warning BUG: no fingerprint for subkeys!
    return [self subStringAttributesWithIdentifier:GPGME_ATTR_FPR maxCount:[self subkeysCount]];
}

- (unsigned int) algorithm
/*"
 * Returns main key algorithm.
"*/
{
    return (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_ALGO, NULL, 0);
}

- (NSArray *) subkeysAlgorithms
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns main key length.
"*/
{
    return (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_LEN, NULL, 0);
}

- (NSArray *) subkeysLengths
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns main key creation date. Returns nil when not available or invalid.
"*/
{
    unsigned long	aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CREATED, NULL, 0);

    if(aValue == 0L)
        return nil;
    else
        return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}

- (NSArray *) subkeysCreationDates
/*"
 * Returns an array of #NSCalendarDate instances. Array values can be
 * #{+[NSValue:valueWithPointer:nil]} when corresponding creation date is not
 * available or invalid.
"*/
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
/*"
 * Returns primary userID.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_USERID];
}

- (NSArray *) userIDs
/*"
 * Returns primary userID, followed by other userIDs.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_USERID maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) name
/*"
 * Returns primary userID name.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_NAME];
}

- (NSArray *) names
/*"
 * Returns primary userID name, followed by other userIDs names.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_NAME maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) email
/*"
 * Returns primary userID email.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_EMAIL];
}

- (NSArray *) emails
/*"
 * Returns primary userID email, followed by other userIDs emails.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_EMAIL maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) comment
/*"
 * Returns primary userID comment.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_COMMENT];
}

- (NSArray *) comments
/*"
 * Returns primary userID comment, followed by other userIDs comments.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_COMMENT maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (GPGValidity) validity
/*"
 * Returns primary userID validity.
"*/
{
    return gpgme_key_get_ulong_attr(_key, GPGME_ATTR_VALIDITY, NULL, 0);
}

- (NSArray *) validities
/*"
 * Returns primary userID validity, followed by other userIDs validities.
"*/
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
/*"
 * Returns whether main key has been revoked.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_REVOKED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysRevocationStatuses
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns whether main key is invalid (e.g. due to a missing self-signature).
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_INVALID, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysValidityStatuses
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns whether main key has expired.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_EXPIRED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysExpirationStatuses
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns whether main key is disabled.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_DISABLED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysActivityStatuses
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns whether primary userID has been revoked.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_REVOKED, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsRevocationStatuses
/*"
 * Returns an array of #NSNumber instances. First value is for primary userID.
"*/
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
/*"
 * Returns whether primary userID is invalid.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_INVALID, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsValidityStatuses
/*"
 * Returns an array of #NSNumber instances. First value is for primary userID.
"*/
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
/*"
 * Returns global encryption capability of the key.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_ENCRYPT, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanEncrypt
/*"
 * Returns whether main key can be used for encyption.
"*/
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 'e') != NULL;
}

- (NSArray *) subkeysEncryptionCapabilities
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns global signature capability of the key.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_SIGN, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanSign
/*"
 * Returns whether main key can be used for signing.
"*/
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 's') != NULL;
}

- (NSArray *) subkeysSigningCapabilities
/*"
 * Returns an array of #NSNumber instances.
"*/
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
/*"
 * Returns global certification capability of the key.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_CERTIFY, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanCertify
/*"
 * Returns whether main key can be used for certification.
"*/
{
    return strchr(gpgme_key_get_string_attr(_key, GPGME_ATTR_KEY_CAPS, NULL, 0), 'c') != NULL;
}

- (NSArray *) subkeysCertificationCapabilities
/*"
 * Returns an array of #NSNumber instances.
"*/
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
