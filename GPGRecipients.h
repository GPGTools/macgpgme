//
//  GPGRecipients.h
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

#import <GPGME/GPGObject.h>


@class NSEnumerator;


/*"
 * The #GPGValidity type is used to specify the validity of a %{user ID} in a key.
 * The following validities are defined:
 * _{GPGValidityUnknown    The %{user ID} is of unknown validity.}
 * _{GPGValidityUndefined  No value assigned. The validity of the %{user ID} is undefined.}
 * _{GPGValidityNever      The %{user ID} is never valid.}
 * _{GPGValidityMarginal   The %{user ID} is marginally valid.}
 * _{GPGValidityFull       The %{user ID} is fully valid.}
 * _{GPGValidityUltimate   The %{user ID} is ultimately valid. Only used for keys for which the secret key is also available.}
"*/
typedef enum {
    GPGValidityUnknown   = 0,
    GPGValidityUndefined = 1,
    GPGValidityNever     = 2,
    GPGValidityMarginal  = 3,
    GPGValidityFull      = 4,
    GPGValidityUltimate  = 5
} GPGValidity;


@interface GPGRecipients : GPGObject /*"NSObject"*/
{
}

- (id) init;

- (void) addName:(NSString *)name;
- (void) addName:(NSString *)name withValidity:(GPGValidity)validity;

- (unsigned int) count;

- (NSEnumerator *) recipientNameEnumerator;

@end
