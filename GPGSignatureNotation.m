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


@implementation GPGSignatureNotation
/*"
 * You can attach arbitrary notation data to a signature. This information is
 * then available to the user when the signature is verified.
"*/

#define _notation		((gpgme_sig_notation_t)aPtr)
- (id) initWithInternalRepresentation:(void *)aPtr
{
    NSParameterAssert(aPtr != NULL);
    
    if(self = [super initWithInternalRepresentation:NULL]){
        const char  *aCString = _notation->name;
        
        if(aCString != NULL)
            _name = [[NSString alloc] initWithBytes:aCString length:_notation->name_len encoding:NSUTF8StringEncoding];
        
        aCString = _notation->value;
        
        if(aCString != NULL){
            if(_notation->name == NULL || !!_notation->human_readable)
                _value = [[NSString alloc] initWithBytes:aCString length:_notation->value_len encoding:NSUTF8StringEncoding];
        }
        else
            _value = [[NSData alloc] initWithBytes:aCString length:_notation->value_len];
        
        _flags = _notation->flags;
        _isHumanReadable = !!_notation->human_readable;
        _isCritical = !!_notation->critical;
    }
    
    return self;
}
#undef _notation

- (void) dealloc
{
    [_name release];
    [_value release];
    
    [super dealloc];
}

- (NSString *) name
/*"
 * The name of the notation field. If this is nil, then the value will contain a
 * policy URL (string).
"*/
{
    return _name;
}

- (id) value
/*"
 * The value of the notation field. If -name returns nil, then value is a policy
 * URL (string). Else, if value is human-readable, a NSString is returned, else
 * a NSData is returned.
"*/
{
    return _value;
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
    return _flags;
}

- (BOOL) isHumanReadable
/*"
 * Convenience method. Returns whether flags indicates that notation data is 
 * human-readable or not; policy URL notation data always return NO. When 
 * returns YES, value is a NSString, else value is a NSData (except for policy 
 * URLs which are always strings).
"*/
{
    return _isHumanReadable;
}

- (BOOL) isCritical
/*"
 * Convenience method. Returns whether flags indicates that notation data is 
 * critical or not.
 *
 * #WARNING: with gpg <= 1.4.x, always return NO
"*/
{
    return _isCritical;
}

- (NSString *) description
{
    NSString    *aName = [self name];
    
    if(aName != nil)
        return [NSString stringWithFormat:@"%@%@ = \"%@\"", ([self isCritical] ? @"!":@""), aName, ([self isHumanReadable] ? [self value]:[[self value] propertyList])];
    else
        return [NSString stringWithFormat:@"%@%@", ([self isCritical] ? @"!":@""), [self value]];
}

@end
