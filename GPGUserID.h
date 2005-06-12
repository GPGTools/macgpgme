//
//  GPGUserID.h
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Fri Dec 27 2002.
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

#ifndef GPGUSERID_H
#define GPGUSERID_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGKey.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class GPGKeySignature;


@interface GPGUserID : GPGObject <NSCopying> /*"NSObject"*/
{
    GPGKey	*_key; /*"Key owning the user ID; not retained"*/
    NSArray	*_signatures; /*"Signatures on the user ID"*/
    int		_refCount;
}

- (NSString *) description;
- (NSString *) userID;
- (GPGKey *) key;

/*"
 * Attributes
"*/
- (NSString *) name;
- (NSString *) comment;
- (NSString *) email;
- (GPGValidity) validity;
- (BOOL) hasBeenRevoked;
- (BOOL) isInvalid;

/*"
 * Convenience methods
"*/
- (NSString *) validityDescription;

/*"
 * Signatures
"*/
- (NSArray *) signatures;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGUSERID_H */
