//
//  GPGSignatureNotation.m
//  MacGPGME
//
//  Created by Dave Lopper on 10/9/05.
//  Copyright 2005 __MyCompanyName__. All rights reserved.
//

#include <MacGPGME/GPGSignatureNotation.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _notation		((gpgme_sig_notation_t)_internalRepresentation)


#warning Subclass NSObject and copy data in ivars
@implementation GPGSignatureNotation
/*"
 * You can attach arbitrary notation data to a signature. This information is
 * then available to the user when the signature is verified.
"*/

- (NSString *) name
/*"
 * The name of the notation field. If this is nil, then the value will contain a
 * policy URL (string).
"*/
{
    const char  *aCString = _notation->name;
    NSString    *aName;
    
    if(aCString != NULL){
        aName = [[NSString alloc] initWithBytes:aCString length:_notation->name_len encoding:NSUTF8StringEncoding];
        [aName autorelease];
    }
    else
        aName = nil;
    
    return aName;
}

- (id) value
/*"
 * The value of the notation field. If -name returns nil, then value is a policy
 * URL (string). Else, if value is human-readable, a NSString is returned, else
 * a NSData is returned.
"*/
{
    const char  *aCString = _notation->value;
    id          aValue;
    
    if(aCString != NULL){
        if(_notation->name == NULL || !!_notation->human_readable){
            aValue = [[NSString alloc] initWithBytes:aCString length:_notation->value_len encoding:NSUTF8StringEncoding];
            [aValue autorelease];
        }
        else
            aValue = [NSData dataWithBytes:aCString length:_notation->value_len];
    }
    else
        aValue = nil;
    
    return aValue;
}

- (GPGSignatureNotationFlags) flags
/*"
 * The accumulated flags field. This field contains the flags associated with
 * the notation data in an accumulated form which can be used as an argument
 * to the method #{-[GPGContext addSignatureNotationWithName:value:flags:]}. The
 * value flags is a bitwise-or combination of one or multiple of the following 
 * bit values: #GPGSignatureNotationHumanReadableMask and 
 * #GPGSignatureNotationCriticalMask. 
"*/
{
    return _notation->flags;
}

- (BOOL) isHumanReadable
/*"
 * Convenience method. Returns whether flags indicates that notation data is 
 * human-readable or not; policy URL notation data always return NO. When 
 * returns YES, value is a NSString, else value is a NSData (except for policy 
 * URLs which are always strings).
"*/
{
    return !!_notation->human_readable;
}

- (BOOL) isCritical
/*"
 * Convenience method. Returns whether flags indicates that notation data is 
 * critical or not.
"*/
{
    return !!_notation->critical;
}

@end
