//
//  GPGSubkey.h
//  GPGME
//
//  Created by davelopper at users.sourceforge.net on Sun Jun 08 2003.
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

#ifndef GPGSUBKEY_H
#define GPGSUBKEY_H

#include <GPGME/GPGKey.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@interface GPGSubkey : GPGKey /*"GPGObject : NSObject"*/
{
    GPGKey	*_key; /*"Key owning the subkey; not retained"*/
    int		_refCount;
}

- (GPGKey *) key;

- (BOOL) isKeyRevoked;
- (BOOL) isKeyInvalid;
- (BOOL) hasKeyExpired;
- (BOOL) isKeyDisabled;

- (BOOL) isSecret;
- (GPGPublicKeyAlgorithm) algorithm;
- (unsigned int) length;
- (NSString *) keyID;
- (NSString *) fingerprint;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;

/*"
 * Global subkey capabilities
"*/
- (BOOL) canEncrypt;
- (BOOL) canSign;
- (BOOL) canCertify;
- (BOOL) canAuthenticate;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGSUBKEY_H */
