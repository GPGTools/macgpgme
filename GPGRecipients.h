//
//  GPGRecipients.h
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

#import <GPGME/GPGObject.h>


typedef enum {
    GPGValidityUnknown   = 0,
    GPGValidityUndefined = 1, // No value assigned
    GPGValidityNever     = 2,
    GPGValidityMarginal  = 3,
    GPGValidityFull      = 4,
    GPGValidityUltimate  = 5  // Only used for keys for which the secret key is also available
} GPGValidity;


@interface GPGRecipients : GPGObject
{
}

- (id) init;
// Designated initializer
// Can raise a GPGException; in this case, a release is sent to self

- (void) addName:(NSString *)name;
// name is a userID (user's name, email address, keyID, etc.)
// Uses GPGValidityUnknown as validity
// Can raise a GPGException
- (void) addName:(NSString *)name withValidity:(GPGValidity)validity;
// name is a userID (user's name, email address, keyID, etc.)
// Can raise a GPGException

- (unsigned int) count;

- (NSEnumerator *) recipientNameEnumerator;
// Enumerated objects are recipient names, represented as NSString instances
// Can raise a GPGException, even during enumeration!

@end
