//
//  GPGRecipients.m
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

#import "GPGRecipients.h"
#import "GPGExceptions.h"
#import "GPGInternals.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _recipients	((GpgmeRecipients)_internalRepresentation)


@interface GPGRecipientNameEnumerator : NSEnumerator
{
    GPGRecipients	*recipients;
    void			*enumerationContext;
}

- (id) initForRecipients:(GPGRecipients *)recipients;
// Designated initializer.
// Can raise a GPGException; in this case, a release is sent to self.

@end


@implementation GPGRecipients
/*"
 * A #GPGRecipients instance is a set of %recipients that can be used in an encryption process.
"*/

- (id) init
/*"
 * Designated initializer. %Recipients set is empty.
 * 
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError = gpgme_recipients_new((GpgmeRecipients *)&_internalRepresentation);

    if(anError != GPGME_No_Error){
        _internalRepresentation = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }

    self = [self initWithInternalRepresentation:_internalRepresentation];

    return self;
}

- (void) dealloc
{
    GpgmeRecipients	cachedRecipients = _recipients;
    
    [super dealloc];

    if(cachedRecipients != NULL)
        gpgme_recipients_release(cachedRecipients);
}

- (void) addName:(NSString *)name
/*"
 * Adds the %recipients name to the set of %recipients.
 *
 * name is a %{user ID} (user's name, email address, %{key ID}, etc.).
 * Uses #GPGValidityUnknown as validity.
 * 
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_recipients_add_name(_recipients, (name != nil ? [name UTF8String]:NULL));

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (void) addName:(NSString *)name withValidity:(GPGValidity)validity
/*"
 * Adds the %recipients name with the validity validity to the set of %recipients.
 *
 * name is a %{user ID} (user's name, email address, %{key ID}, etc.).
 * 
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_recipients_add_name_with_validity(_recipients, (name != nil ? [name UTF8String]:NULL), validity);

    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (unsigned int) count
/*"
 * Returns the number of %recipients in the set.
"*/
{
    return gpgme_recipients_count(_recipients);
}

- (NSEnumerator *) recipientNameEnumerator
/*"
 * Enumerated objects are %recipient names, represented as #NSString instances.
 * Returned names are the ones set with #{-addName:} and #{-addName:withValidity:}.
 * 
 * Can raise a #GPGException, even during enumeration!
"*/
{
    return [[[GPGRecipientNameEnumerator alloc] initForRecipients:self] autorelease];
}

#warning TODO
/* 
    We could also add the following calls:
    - (void) addKey:(GPGKey *)key
    - (void) addKey:(GPGKey *)key withValidity:(GPGValidity)validity
    - (NSEnumerator *) keyEnumerator (but we need to create a local context to get a named key)
    
    Currently there is no way to copy a recipients set, because we can't enumerate
    the associated validities. This will be implemented later in libgpgme.
*/
@end


@implementation GPGRecipients(GPGInternals)

- (GpgmeRecipients) gpgmeRecipients
{
    return _recipients;
}

@end


@implementation GPGRecipientNameEnumerator

- (id) initForRecipients:(GPGRecipients *)theRecipients
{
    if(self = [self init]){
        GpgmeError	anError = gpgme_recipients_enum_open([theRecipients gpgmeRecipients], &enumerationContext);

        if(anError != GPGME_No_Error){
            [self release];
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        }
        else
            // We retain theRecipients, to avoid it to be released before we are finished
            recipients = [theRecipients retain];
    }

    return self;
}

- (void) dealloc
{
    GpgmeError	anError = GPGME_No_Error;

    if(recipients != nil){
        anError = gpgme_recipients_enum_close([recipients gpgmeRecipients], &enumerationContext);
        [recipients release];
    }

    [super dealloc];

    // Let's raise the exception after the deallocation
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (id) nextObject
{
    const char	*aBuffer;
    NSString	*aString;

    if(recipients == nil)
        return nil;

    aBuffer = gpgme_recipients_enum_read([recipients gpgmeRecipients], &enumerationContext); // Returns NULL when there's nothing more to read
    if(aBuffer == NULL){
        GpgmeError	anError = gpgme_recipients_enum_close([recipients gpgmeRecipients], &enumerationContext);

        [recipients release];
        recipients = nil;
        if(anError != GPGME_No_Error && anError != GPGME_EOF)
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        else
            return nil;
    }

    aString = [NSString stringWithUTF8String:aBuffer];

    return aString;
}

@end

