//
//  GPGTrustItem.m
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

#import "GPGTrustItem.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _trustItem	((GpgmeTrustItem)_internalRepresentation)


@implementation GPGTrustItem
/*"
 * You should never need to instantiate objects of that class. GPGContext does
 * it for you.
"*/

- (void) dealloc
{
    GpgmeTrustItem	cachedTrustItem = _trustItem;
    
    [super dealloc];

    gpgme_trust_item_release(cachedTrustItem);
}

- (NSString *) keyID
{
    const char	*aCString = gpgme_trust_item_get_string_attr(_trustItem, GPGME_ATTR_KEYID, NULL, 0);
    NSString	*aString = nil;

    if(aCString != NULL)
        aString = [NSString stringWithUTF8String:aCString];

    return aString;
}

- (GPGValidity) validityFromCharacter:(char)character
{
    switch(character){
        case 'q':
            return GPGValidityUnknown;
        case 'n':
            return GPGValidityNever;
        case 'm':
            return GPGValidityMarginal;
        case 'f':
            return GPGValidityFull;
        case 'u':
            return GPGValidityUltimate;
        default:
            [NSException raise:NSInternalInconsistencyException format:@"Unknown trust value '%c'", character];
            return -1; // Never reached; just here to make compiler happy ;-)
    }
}

- (GPGValidity) ownerTrust
{
    const char	*aCString = gpgme_trust_item_get_string_attr(_trustItem, GPGME_ATTR_OTRUST, NULL, 0);

    if(aCString != NULL){
        NSAssert1(strlen(aCString) == 1, @"We cannot decode this ownerTrust value: %s", aCString);

        return [self validityFromCharacter:aCString[0]];
    }

    return GPGValidityUnknown;
}

- (NSString *) userID
{
    const char	*aCString = gpgme_trust_item_get_string_attr(_trustItem, GPGME_ATTR_USERID, NULL, 0);
    NSString	*aString = nil;

    if(aCString != NULL)
        aString = [NSString stringWithUTF8String:aCString];

    return aString;
}

- (GPGValidity) validity
/*"
 * Returns the computed validity.
"*/
{
    const char	*aCString = gpgme_trust_item_get_string_attr(_trustItem, GPGME_ATTR_VALIDITY, NULL, 0);

    if(aCString != NULL){
        NSAssert1(strlen(aCString) == 1, @"We cannot decode this validity value: %s", aCString);

        return [self validityFromCharacter:aCString[0]];
    }

    return GPGValidityUnknown;
}

- (int) level
{
    return gpgme_trust_item_get_int_attr(_trustItem, GPGME_ATTR_LEVEL, NULL, 0);
}

- (int) type
{
#warning What is the <type> attribute???
    return gpgme_trust_item_get_int_attr(_trustItem, GPGME_ATTR_TYPE, NULL, 0);
}

@end
