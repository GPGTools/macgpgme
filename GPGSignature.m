//
//  GPGSignature.m
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Sun Jul 14 2002.
//
//
//  Copyright (C) 2002 Mac GPG Project.
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

#include <GPGME/GPGSignature.h>
#include <GPGME/GPGInternals.h>
#include <GPGME/GPGPrettyInfo.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _context	((GPGContext *)_internalRepresentation)


@implementation GPGSignature
/*"
 * #GPGSignature instances are returned by #{-[GPGContext signatures]};
 * you should never need to instantiate yourself objects of that class.
"*/

- (id) initWithContext:(GPGContext *)ctx index:(unsigned)index
{
    if(self = [self init]){
        _context = ctx; // Not retained
        _index = index;
    }

    return self;
}

- (BOOL) isEqual:(id)anObject
{
    if(anObject != nil && [anObject isKindOfClass:[GPGSignature class]])
        return (_context == ((GPGSignature *)anObject)->_internalRepresentation) && (_index == ((GPGSignature *)anObject)->_index);
    else
        return NO;
}

- (NSString *) mainStringAttributeWithIdentifier:(GpgmeAttr)identifier
{
    const char	*aCString = gpgme_get_sig_string_attr([_context gpgmeContext], _index, identifier, 0);

    if(aCString != NULL)
        return [NSString stringWithUTF8String:aCString];
    else
        return nil;
}

- (NSString *) fingerprint
/*"
 * Returns signer key %fingerprint.
"*/
{
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_FPR];
}

- (GPGKey *) key
/*"
 * Returns signer key.
 * 
 * Can raise a #GPGException (except a #GPGErrorEOF).
"*/
{
    return [_context keyOfSignatureAtIndex:_index];
}

- (NSString *) errorToken
{
#warning What is it for?
    return [self mainStringAttributeWithIdentifier:GPGME_ATTR_ERRTOK];
}

- (NSString *) suberrorToken
{
#warning What is it for?
    const char	*aCString = gpgme_get_sig_string_attr([_context gpgmeContext], _index, GPGME_ATTR_ERRTOK, 1);

    if(aCString != NULL)
        return [NSString stringWithUTF8String:aCString];
    else
        return nil;
}

- (NSCalendarDate *) creationDate
/*"
 * Returns signature creation date. Returns nil when not available or invalid.
"*/
{
    unsigned long	aValue = gpgme_get_sig_ulong_attr([_context gpgmeContext], _index, GPGME_ATTR_CREATED, 0);

    if(aValue == 0L)
        return nil;
    else
        return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}

- (NSCalendarDate *) expirationDate
/*"
 * Returns signature expiration date. Returns nil when not available or invalid.
"*/
{
    unsigned long	aValue = gpgme_get_sig_ulong_attr([_context gpgmeContext], _index, GPGME_ATTR_EXPIRE, 0);

    if(aValue == 0L)
        return nil;
    else
        return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}

- (GPGValidity) validity
/*"
 * Returns signature's validity.
"*/
{
    return gpgme_get_sig_ulong_attr([_context gpgmeContext], _index, GPGME_ATTR_VALIDITY, 0);
}

- (NSString *) validityDescription
/*"
 * Returns signature's validity in localized human readable form.
"*/
{
    return GPGValidityDescription([self validity]);
}

- (GPGSignatureStatus) status
/*"
 * Returns signature status.
"*/
{
    return gpgme_get_sig_ulong_attr([_context gpgmeContext], _index, GPGME_ATTR_SIG_STATUS, 0);
}

- (GPGSignatureSummaryMask) summary
/*"
 * Returns a mask reflecting the computed state of all signatures.
"*/
{
    return gpgme_get_sig_ulong_attr([_context gpgmeContext], _index, GPGME_ATTR_SIG_SUMMARY, 0);
}

@end
