//
//  GPGTrustItem.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2003 Mac GPG Project.
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

#ifndef GPGTRUSTITEM_H
#define GPGTRUSTITEM_H

#include <GPGME/GPGObject.h>
#include <GPGME/GPGRecipients.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSString;


@interface GPGTrustItem : GPGObject /*"NSObject"*/
{
}

- (NSString *) keyID;
- (GPGValidity) ownerTrust;
- (NSString *) ownerTrustDescription;
- (NSString *) userID;
- (GPGValidity) validity;
- (NSString *) validityDescription;
- (int) level;
- (int) type;

+ (NSString *) ownerTrustDescription: (GPGValidity)value;
+ (NSString *) validityDescription: (GPGValidity)value;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGTRUSTITEM_H */
