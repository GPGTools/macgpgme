//
//  GPGRemoteKey.h
//  MacGPGME
//
//  Created by Robert Goldsmith (r.s.goldsmith@far-blue.co.uk) on Sat July 9 2005.
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

#ifndef GPGREMOTEKEY_H
#define GPGREMOTEKEY_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGEngine.h>
#include <MacGPGME/GPGContext.h>
#include <MacGPGME/GPGKeyDefines.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@interface GPGRemoteKey : GPGObject <NSCopying> /*"NSObject"*/
{
  NSArray	*_userIDs; /*"Array containing GPGRemoteUserID instances"*/
  NSArray	*_colonFormatStrings;
  int		_version;
}

- (unsigned) hash;
- (BOOL)isEqual:(id)anObject;

- (NSDictionary *) dictionaryRepresentation;

- (NSString *) shortKeyID;
- (NSString *) keyID;
- (GPGPublicKeyAlgorithm) algorithm;
- (NSString *) algorithmDescription;
- (unsigned int) length;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;
- (BOOL) isKeyRevoked;
- (BOOL) hasKeyExpired;

- (NSString *) userID;

- (NSArray *) userIDs;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGREMOTEKEY_H */

