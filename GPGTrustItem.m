//
//  GPGTrustItem.m
//  GPGME
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

#include <GPGME/GPGTrustItem.h>
#include <GPGME/GPGPrettyInfo.h>
#include <GPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _trustItem	((gpgme_trust_item_t)_internalRepresentation)


@implementation GPGTrustItem
/*"
 * #GPGTrustItem instances are returned by
 * #{-[GPGContext trustListEnumeratorForSearchPattern:maximumLevel:]}; you
 * should never need to instantiate objects of that class.
 *
 * #CAUTION: the trust items interface is experimental.
"*/

+ (BOOL) needsPointerUniquing
{
    return YES;
}

- (void) dealloc
{
    gpgme_trust_item_t	cachedTrustItem = _trustItem;
    
    [super dealloc];

    gpgme_trust_item_unref(cachedTrustItem);
}

- (NSString *) keyID
/*"
 * Returns the %{key ID} of the %key refered by the trust item.
"*/
{
    return GPGStringFromChars(_trustItem->keyid);
}

- (NSString *) ownerTrustDescription
/*"
 * #CAUTION: not yet working. Only if type = 1.
"*/
{
    return GPGStringFromChars(_trustItem->owner_trust);
}

- (NSString *) name
/*"
 * Returns the %{name} associated with the trust item. Only if type = 2.
"*/
{
    return GPGStringFromChars(_trustItem->name);
}

- (NSString *) validityDescription
/*"
 * Returns the computed validity associated with the trust item.
"*/
{
    return GPGStringFromChars(_trustItem->validity);
}

- (int) level
/*"
 * Returns the trust level of the trust item.
"*/
{
    return _trustItem->level;
}

- (int) type
/*"
 * Returns the type of the trust item. A value of 1 refers to a key, a value
 * of 2 refers to a user ID.
 *
 * #CHECK: not yet working.
"*/
{
    return _trustItem->type;
}

#warning TODO
/*
    We could also implement the following calls:
    - (GPGKey *) key
    (we need to create a local context to get the named key; key should be cached)
*/

@end
