//
//  GPGKey.m
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

#import "GPGKey.h"
#import "GPGPrettyInfo.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _key	((GpgmeKey)_internalRepresentation)


@implementation GPGKey
/*"
 * Some of the cryptographic operations require that %recipients or %signers are specified.
 * This is always done by specifying the respective %keys that should be used for the operation.
 * GPGKey instances represent %public or %secret %keys.
 *
 * A %key can contain several %{user IDs} and %{sub keys}.
 *
 * #GPGKey instances are returned by #{-[GPGContext keyEnumeratorForSearchPattern:secretKeysOnly:]},
 * #{-[GPGContext keyOfSignatureAtIndex:]};
 * you should never need to instantiate objects of that class.
 *
 * Two #GPGKey instances are considered equal (in GPGME) if they have the same %fingerprint.
 * #GPGKey instances are (currently) immutable.
"*/

- (void) dealloc
{
    GpgmeKey	cachedKey = _key;
    
    [super dealloc];

    gpgme_key_unref(cachedKey);
}

- (unsigned) hash
/*"
 * Returns hash value based on %fingerprint.
"*/
{
    NSString	*fingerprint = [self fingerprint];
    
    if(fingerprint != nil)
        return [fingerprint hash];
    // WARNING: we don't take in account if key is secret or not!!!
    return [super hash];
}

- (BOOL) isEqual:(id)anObject
/*"
 * Returns YES if both the receiver and anObject have the same %fingerprint.
"*/
{
    if(anObject != nil && [anObject isKindOfClass:[GPGKey class]]){
        NSString	*fingerprint = [self fingerprint];
    
        if(fingerprint != nil){
            NSString	*otherFingerprint = [anObject fingerprint];
        
            if(otherFingerprint != nil && [otherFingerprint isEqualToString:fingerprint] /*&& [self hasSecretPart] == [anObject hasSecretPart]*/)
                return YES;
        }
    }
    return NO;
}

- (id) copyWithZone:(NSZone *)zone
/*"
 * Returns the same instance, retained. #GPGKey instances are (currently) immutable.
 *
 * #WARNING: zone is not taken in account.
"*/
{
    // Implementation is useful to allow use of GPGKey instances as keys in NSMutableDictionary instances.
    return [self retain];
}

- (GPGKey *) publicKey
/*"
 * If key is the public key, returns self, else returns the corresponding secret key
 * if there is one, else nil.
"*/
{
    if(![self hasSecretPart])
        return self;
    else{
        GPGContext	*aContext = [[GPGContext alloc] init];
        GPGKey		*aKey;

        aKey = [[aContext keyEnumeratorForSearchPattern:[@"0x" stringByAppendingString:[self fingerprint]] secretKeysOnly:NO] nextObject]; // We assume that there is only one key returned (with the same fingerprint)
        [aKey retain];
        [aContext release];

        return [aKey autorelease];
    }
}

- (GPGKey *) secretKey
/*"
 * If key is the secret key, returns self, else returns the corresponding public key
 * if there is one, else nil.
"*/
{
    if([self hasSecretPart])
        return self;
    else{
        GPGContext	*aContext = [[GPGContext alloc] init];
        GPGKey		*aKey;

        aKey = [[aContext keyEnumeratorForSearchPattern:[@"0x" stringByAppendingString:[self fingerprint]] secretKeysOnly:YES] nextObject]; // We assume that there is only one key returned (with the same fingerprint)
        [aKey retain];
        [aContext release];

        return [aKey autorelease];
    }
}

- (NSString *) descriptionAsXMLString
/*"
 * Returns a string in XML format describing the key. It never returns nil.
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
 *     <expire>aTime</expire>
 *     <serial>issuerSerial</serial>
 *     <issuer>issuerName</issuer>
 *     <chainid>chainID</chainid>
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
 *     <expire>aTime</expire>
 *   </subkey>
 * </GnupgKeyblock>}
"*/
{
    char		*aBuffer = gpgme_key_get_as_xml(_key);
    NSString	*aString;

    NSAssert(aBuffer != NULL, @"### Unable to make an XML description.");
    aString = [NSString stringWithUTF8String:aBuffer];
    free(aBuffer);
    
    return aString;
}

/*
- (NSDictionary *) dictionaryRepresentationForUserIDAtIndex:(unsigned)index
{
    int					i;
    unsigned			userIDCount = [self secondaryUserIDsCount] + 1;
    NSMutableDictionary	*dictionaryRepresentation;

    NSParameterAssert(index < userIDCount);
    
    dictionaryRepresentation = [NSMutableDictionary dictionary];
    //    uids = [self userIDs];
    //    uids_invalid_sts = [self userIDsValidityStatuses];
    //    uids_revoked_sts = [self userIDsRevocationStatuses];
    //    uids_names = [self names];
    //    uids_emails = [self emails];
    //    uids_comments = [self comments];
        id					aValue;

        [userIDDictionaryRepresentations addObject:userIDDictionaryRepresentation];
        aValue = [uids_invalid_sts objectAtIndex:i];
        if(aValue != nil)
            [aUserIDDictionaryRepresentation setObject:aValue forKey:@"invalid"];
        if ([uids_revoked_sts objectAtIndex:i])
            [aUserIDDictionaryRepresentation setObject:
             [uids_revoked_sts objectAtIndex:i] forKey:@"revoked"];
        if ([uids objectAtIndex:i])
            [aUserIDDictionaryRepresentation setObject:
                         [uids objectAtIndex:i] forKey:@"raw"];
        if ([uids_names objectAtIndex:i])
            [aUserIDDictionaryRepresentation setObject:
                   [uids_names objectAtIndex:i] forKey:@"name"];
        if ([uids_emails objectAtIndex:i])
            [aUserIDDictionaryRepresentation setObject:
                  [uids_emails objectAtIndex:i] forKey:@"email"];
        if ([uids_comments objectAtIndex:i])
            [aUserIDDictionaryRepresentation setObject:
                [uids_comments objectAtIndex:i] forKey:@"comment"];
}
*/

- (NSDictionary *) dictionaryRepresentation
/*"
 * #Caution:  if the user changes libgpgme.a out from under GPGME.framework
 * then this will not return the same as #{-descriptionAsXMLString}.
 *
 * Returns a dictionary that looks something like this:
 *
 * !{{
 * algo = 17; 
 * created = 2000-07-13 08:35:05 -0400; 
 * expire = 2010-07-13 08:35:05 -0400; 
 * disabled = 0; 
 * expired = 0; 
 * fpr = C462FA84B8113501901020D26EF377F7BBD3B003; 
 * invalid = 0; 
 * keyid = 6EF377F7BBD3B003; 
 * shortkeyid = BBD3B003; 
 * len = 1024; 
 * revoked = 0; 
 * secret = 1;
 * issuerSerial = XX;
 * issuerName = XX;
 * chainID = XX;
 * ownertrust = 1;
 * subkeys = (
 * 		{
 *         algo = 16; 
 *         created = 2000-07-13 08:35:06 -0400; 
 *         expire = 2010-07-13 08:35:06 -0400; 
 *         disabled = 0; 
 *         expired = 0; 
 *         fpr = ""; 
 *         invalid = 0; 
 *         keyid = 5745314F70E767A9; 
 *         len = 2048; 
 *         revoked = 0; 
 *     }
 * ); 
 * userids = (
 *     {
 *         comment = "Gordon Worley <redbird@mac.com>"; 
 *         email = "Gordon Worley <redbird@mac.com>"; 
 *         invalid = 0; 
 *         name = "Gordon Worley <redbird@mac.com>"; 
 *         raw = "Gordon Worley <redbird@mac.com>"; 
 *         revoked = 0; 
 *     }, 
 *     {
 *         comment = ""; 
 *         email = ""; 
 *         invalid = 0; 
 *         name = "[image of size 2493]"; 
 *         raw = "[image of size 2493]"; 
 *         revoked = 0; 
 *     }, 
 *     {
 *         comment = ""; 
 *         email = "redbird@rbisland.cx"; 
 *         invalid = 0; 
 *         name = "Gordon Worley"; 
 *         raw = "Gordon Worley <redbird@rbisland.cx>"; 
 *         revoked = 0; 
 *     }
 * );
 * }}
"*/
{
    NSMutableDictionary *key_dict = [NSMutableDictionary dictionary];
    NSArray *uids, *uids_invalid_sts, *uids_revoked_sts, *uids_names, *uids_emails, *uids_comments,
            *uids_validities,
            *subkeys, *sks_short_keyids, *sks_invalid_sts, *sks_revoked_sts, *sks_expired_sts,
        *sks_disabled_sts, *sks_fprs, *sks_algos, *sks_lens, *sks_cre_dates, *sks_exp_dates;
    int i;
    
    [key_dict setObject: [NSNumber numberWithBool:[self hasSecretPart]] forKey:@"secret"];
    [key_dict setObject: [NSNumber numberWithBool:[self isKeyInvalid]] forKey:@"invalid"];
    [key_dict setObject: [NSNumber numberWithBool:[self isKeyRevoked]] forKey:@"revoked"];
    [key_dict setObject: [NSNumber numberWithBool:[self hasKeyExpired]] forKey:@"expired"];
    [key_dict setObject: [NSNumber numberWithBool:[self isKeyDisabled]] forKey:@"disabled"];
    [key_dict setObject: [self shortKeyID] forKey: @"shortkeyid"];
    [key_dict setObject: [self keyID] forKey: @"keyid"];
    [key_dict setObject: [self fingerprint] forKey:@"fpr"];
    [key_dict setObject: [NSNumber numberWithInt:[self algorithm]] forKey:@"algo"];
    [key_dict setObject: [NSNumber numberWithInt:[self length]] forKey:@"len"];
    if ([self creationDate])
        [key_dict setObject: [self creationDate] forKey:@"created"];
    if ([self expirationDate])
        [key_dict setObject: [self expirationDate] forKey:@"expire"];
    if ([self issuerSerial])
        [key_dict setObject: [self issuerSerial] forKey:@"issuerSerial"];
    if ([self issuerName])
        [key_dict setObject: [self issuerName] forKey:@"issuerName"];
    if ([self chainID])
        [key_dict setObject: [self chainID] forKey:@"chainID"];
    [key_dict setObject: [NSNumber numberWithInt:[self ownerTrust]] forKey:@"ownertrust"];
    [key_dict setObject: [NSMutableArray array] forKey:@"userids"];
    uids = [self userIDs];
    uids_invalid_sts = [self userIDsValidityStatuses];
    uids_revoked_sts = [self userIDsRevocationStatuses];
    uids_names = [self names];
    uids_emails = [self emails];
    uids_comments = [self comments];
    uids_validities = [self validities];
    for (i = 0; i < [uids count]; i++)	{
        [[key_dict objectForKey:@"userids"] addObject: [NSMutableDictionary dictionary]];
        if ([uids_invalid_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids_invalid_sts objectAtIndex:i] forKey:@"invalid"];
        if ([uids_revoked_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids_revoked_sts objectAtIndex:i] forKey:@"revoked"];
        if ([uids objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids objectAtIndex:i] forKey:@"raw"];
        if ([uids_names objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids_names objectAtIndex:i] forKey:@"name"];
        if ([uids_emails objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids_emails objectAtIndex:i] forKey:@"email"];
        if ([uids_comments objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                [uids_comments objectAtIndex:i] forKey:@"comment"];
        if ([uids_validities objectAtIndex:i])
            [[[key_dict objectForKey:@"userids"] objectAtIndex:i] setObject:
                                     [uids_validities objectAtIndex:i] forKey:@"validity"];
    }
    
    [key_dict setObject: [NSMutableArray array] forKey:@"subkeys"];
    subkeys = [self subkeysKeyIDs];  //keyids
    sks_short_keyids = [self subkeysShortKeyIDs];
    sks_invalid_sts = [self subkeysValidityStatuses];
    sks_revoked_sts = [self subkeysRevocationStatuses];
    sks_expired_sts = [self subkeysExpirationStatuses];
    sks_disabled_sts = [self subkeysActivityStatuses];
    sks_fprs = [self subkeysFingerprints];
    sks_algos = [self subkeysAlgorithms];
    sks_lens = [self subkeysLengths];
    sks_cre_dates = [self subkeysCreationDates];
    sks_exp_dates = [self subkeysExpirationDates];
    for (i = 0; i < [subkeys count]; i++)	{
        [[key_dict objectForKey:@"subkeys"] addObject: [NSMutableDictionary dictionary]];
        if ([sks_invalid_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_invalid_sts objectAtIndex:i] forKey:@"invalid"];
        if ([sks_revoked_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_revoked_sts objectAtIndex:i] forKey:@"revoked"];
        if ([sks_expired_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_expired_sts objectAtIndex:i] forKey:@"expired"];
        if ([sks_disabled_sts objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_disabled_sts objectAtIndex:i] forKey:@"disabled"];
        if ([sks_short_keyids objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_short_keyids objectAtIndex:i] forKey:@"shortkeyid"];
        if ([subkeys objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [subkeys objectAtIndex:i] forKey:@"keyid"];
        if ([sks_fprs objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_fprs objectAtIndex:i] forKey:@"fpr"];
        if ([sks_algos objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_algos objectAtIndex:i] forKey:@"algo"];
        if ([sks_lens objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_lens objectAtIndex:i] forKey:@"len"];
        if ([sks_cre_dates objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_cre_dates objectAtIndex:i] forKey:@"created"];
        if ([sks_exp_dates objectAtIndex:i])
            [[[key_dict objectForKey:@"subkeys"] objectAtIndex:i] setObject:
                [sks_exp_dates objectAtIndex:i] forKey:@"expire"];
    }
        
    return key_dict;
}

+ (NSString *) algorithmDescription:(GPGPublicKeyAlgorithm)value
/*"
 * Returns a localized description of the %{public key algorithm} value.
"*/
{
    return GPGPublicKeyAlgorithmDescription(value);
}

+ (NSString *) validityDescription:(GPGValidity)value
/*"
 * Returns a localized description of the %validity value.
"*/
{
    return GPGValidityDescription(value);
}

+ (NSString *) ownerTrustDescription:(GPGValidity)value
/*"
 * Returns a localized description of the %{owner trust} value.
"*/
{
    return GPGValidityDescription(value);
}

- (NSString *) mainStringAttributeWithIdentifier:(GpgmeAttr)identifier
{
    const char	*aCString = gpgme_key_get_string_attr(_key, identifier, NULL, 0);

    if(aCString != NULL)	{
        //detects whether string is Latin-1 or UTF-8
        char *s;
        
        for (s=aCString; *s && !(*s & 0x80); s++)
            ;
        if (*s && !strchr(aCString, 0xc3))	{
            return [[[NSString alloc] initWithData: [NSData dataWithBytes: aCString length: strlen(aCString)]
                                          encoding: NSISOLatin1StringEncoding] autorelease];
        }
        else
            return [NSString stringWithUTF8String:aCString];    
        }
    else
        return nil;
}

- (NSMutableArray *) subStringAttributesWithIdentifier:(GpgmeAttr)identifier maxCount:(unsigned)maxCount
{
    // If maxCount == 0, we stop enumerating when we get a NULL value,
    // else we replace NULL values with empty strings, and continue
    // up to maxCount. This is a workaround for the missing functions
    // gpgme_key_subkeys_count() and gpgme_key_userids_count().
    // Werner is aware of this, and will provide such a function/attribute.
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

- (NSString *) shortKeyID
/*"
 * Returns %{main key short (128 bit) key ID}.
"*/
{
    return [[self keyID] substringFromIndex:8];
}

- (NSArray *) subkeysShortKeyIDs
/*"
 * Returns an array of #NSString instances.
"*/
{
    NSMutableArray	*keyIDs = [NSMutableArray arrayWithArray:[self subkeysKeyIDs]];
    int				i, count;

    count = [keyIDs count];
    for (i = count - 1; i >= 0; i--)
        [keyIDs replaceObjectAtIndex:i withObject:[[keyIDs objectAtIndex:i] substringFromIndex:8]];
    
    return keyIDs;
}

- (NSString *) keyID
/*"
 * Returns %{main key key ID}.
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
 * Returns %{main key fingerprint}.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_FPR];
}

- (NSArray *) subkeysFingerprints
/*"
 * Returns an array of #NSString instances.
 *
 * #Caution: it does not work currently.
"*/
{
    // BUG: no fingerprint for subkeys! Reported to Werner.
    return [self subStringAttributesWithIdentifier:GPGME_ATTR_FPR maxCount:[self subkeysCount]];
}

- (GPGPublicKeyAlgorithm) algorithm
/*"
 * Returns %{main key algorithm}. The algorithm is the crypto algorithm for which the key can be used.
 * The value corresponds to the #GPGPublicKeyAlgorithm enum values.
"*/
{
    return (GPGPublicKeyAlgorithm)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_ALGO, NULL, 0);
}

- (NSString *) algorithmDescription
{
    return GPGPublicKeyAlgorithmDescription([self algorithm]);
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

- (NSArray *) subkeysAlgorithmDescriptions
/*"
 * Returns an array of #NSString instances.
"*/
{
    int				i = 1;
    unsigned int	aValue, maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = (unsigned int)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_ALGO, NULL, i);
        [attributes addObject:[GPGKey algorithmDescription:aValue]];
    }

    return attributes;
}

- (unsigned int) length
/*"
 * Returns %{main key} length, in bits.
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
 * Returns %{main key} creation date. Returns nil when not available or invalid.
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
 * #{+[NSValue valueWithPointer:nil]} when corresponding creation date is not
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

- (NSCalendarDate *) expirationDate
/*"
 * Returns %{main key} expiration date. Returns nil when there is none
 * or is not available or is invalid.
"*/
{
    unsigned long	aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_EXPIRE, NULL, 0);

    if(aValue == 0L)
        return nil;
    else
        return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}

- (NSArray *) subkeysExpirationDates
/*"
 * Returns an array of #NSCalendarDate instances. Array values can be
 * #{+[NSValue valueWithPointer:nil]} when corresponding expiration date
 * does not exist, is not available or is invalid.
"*/
{
#warning BUG? Seems that expiration date is never returned by gpgme for subkeys
    int				i = 1;
    unsigned long	aValue;
    unsigned		maxCount = [self subkeysCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 1; i <= maxCount; i++){
        aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_EXPIRE, NULL, i);
        if(aValue == 0L)
            [attributes addObject:[NSValue valueWithPointer:nil]];
        else
            [attributes addObject:[NSCalendarDate dateWithTimeIntervalSince1970:aValue]];
    }

    return attributes;
}

- (GPGValidity) ownerTrust
/*"
 * Returns %{owner trust}.
"*/
{
    unsigned long	aValue = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_OTRUST, NULL, 0);

    return aValue;
}

- (NSString *) ownerTrustDescription
/*"
 * Returns a localized description of the %{owner trust}.
"*/
{
    return GPGValidityDescription([self ownerTrust]);
}

- (NSString *) userID
/*"
 * Returns the %{primary user ID}.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_USERID];
}

- (NSArray *) userIDs
/*"
 * Returns the %{primary user ID}, followed by other %{user IDs}.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_USERID maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self userID] atIndex:0];

    return result;
}

- (NSString *) name
/*"
 * Returns the %{primary user ID} name.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_NAME];
}

- (NSArray *) names
/*"
 * Returns the %{primary user ID} name, followed by other %{user IDs} names.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_NAME maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self name] atIndex:0];

    return result;
}

- (NSString *) email
/*"
 * Returns the %{primary user ID} email address.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_EMAIL];
}

- (NSArray *) emails
/*"
 * Returns the %{primary user ID} email address, followed by other %{user IDs} email addresses.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_EMAIL maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self email] atIndex:0];

    return result;
}

- (NSString *) comment
/*"
 * Returns the %{primary user ID} comment.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_COMMENT];
}

- (NSArray *) comments
/*"
 * Returns the %{primary user ID} comment, followed by other %{user IDs} comments.
"*/
{
    NSMutableArray	*result = [self subStringAttributesWithIdentifier:GPGME_ATTR_COMMENT maxCount:[self secondaryUserIDsCount]];

    [result insertObject:[self comment] atIndex:0];

    return result;
}

- (GPGValidity) validity
/*"
 * Returns the %{primary user ID} validity.
"*/
{
    return gpgme_key_get_ulong_attr(_key, GPGME_ATTR_VALIDITY, NULL, 0);
}

- (NSString *) validityDescription
{
    return GPGValidityDescription([self validity]);
}

- (NSArray *) validities
/*"
 * Returns the %{primary user ID} validity, followed by other %{user IDs} validities, as #NSNumber instances.
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

- (NSArray *) validityDescriptions
/*"
 * Returns the %{primary user ID} validity, followed by other
 * %{user IDs} validities, as #NSString instances.
"*/
{
    int				i = 0;
    GPGValidity		aValue;
    unsigned		maxCount = [self secondaryUserIDsCount];
    NSMutableArray	*attributes = [NSMutableArray array];

    for(i = 0; i <= maxCount; i++){
        aValue = (GPGValidity)gpgme_key_get_ulong_attr(_key, GPGME_ATTR_VALIDITY, NULL, i);
        [attributes addObject:[GPGKey validityDescription:aValue]];
    }

    return attributes;
}

- (BOOL) isKeyRevoked
/*"
 * Returns whether %{main key} is revoked.
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
 * Returns whether %{main key} is invalid (e.g. due to a missing self-signature).
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
 * Returns whether %{main key} is expired.
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
 * Returns whether %{main key} is disabled.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_KEY_DISABLED, NULL, 0);

    return (!!result);
}

- (NSArray *) subkeysActivityStatuses
/*"
 * Returns an array of #NSNumber instances, specifying whether corresponding %{sub key} is disabled.
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
 * Returns whether %{primary user ID} is revoked.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_REVOKED, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsRevocationStatuses
/*"
 * Returns the %{primary user ID} revocation status (revoked or not),
 * followed by other %{user IDs} revocation statuses, as #NSNumber instances.
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
 * Returns whether %{primary user ID} is invalid.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_UID_INVALID, NULL, 0);

    return (!!result);
}

- (NSArray *) userIDsValidityStatuses
/*"
 * Returns the %{primary user ID} validity status (#{invalid or not}),
 * followed by other %{user IDs} validity statuses, as #NSNumber instances.
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
/*"
 * If a key has a secret part, than all %{sub keys} are password-protected (i.e. have a secret part too),
 * but password can be different for each %{sub key}.
 * A %{sub key} cannot have a secret part if the key has none.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_IS_SECRET, NULL, 0);

    return (!!result);
}

- (BOOL) canEncrypt
/*"
 * Returns whether the %key can be used for encryption.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_ENCRYPT, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanEncrypt
/*"
 * Returns whether %{main key} can be used for encryption.
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
 * Returns whether the key can be used for signatures.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_SIGN, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanSign
/*"
 * Returns whether %{main key} can be used for signatures.
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
 * Returns whether the key can be used for certifications.
"*/
{
    unsigned long	result = gpgme_key_get_ulong_attr(_key, GPGME_ATTR_CAN_CERTIFY, NULL, 0);

    return (!!result);
}

- (BOOL) mainKeyCanCertify
/*"
 * Returns whether %{main key} can be used for certification.
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

- (NSString *) issuerSerial
/*"
 * Returns the X.509 %{issuer serial} attribute of the key (only for S/MIME).
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_SERIAL];
}

- (NSString *) issuerName
/*"
 * Returns the X.509 %{issuer name} attribute of the key (only for S/MIME).
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_ISSUER];
}

- (NSString *) chainID
/*"
 * Returns the X.509 %{chain ID} that can be used to build the certification chain (only for S/MIME).
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_CHAINID];
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
