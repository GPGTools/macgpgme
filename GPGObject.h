//
//  GPGObject.h
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

#import <Foundation/NSObject.h>


// This abstract class takes care of uniquing instances
// against gpgme internal structs


@interface GPGObject : NSObject
{
    void	*_internalRepresentation;
}

- (id) initWithInternalRepresentation:(void *)aPtr;
// Default initializer; all subclasses must call this method!
// Can return another object than the one which received the message!

- (void) dealloc;
// WARNING: _internalRepresentation pointer MUST still be valid when
// -[GPGObject dealloc] method is called!!!

@end
