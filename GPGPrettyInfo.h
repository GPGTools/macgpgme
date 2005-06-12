//
//  GPGPrettyInfo.h
//  MacGPGME
//
//  Created by Gordon Worley on Tue Jun 18 2002.
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

#ifndef GPGPRETTYINFO_H
#define GPGPRETTYINFO_H

#include <Foundation/Foundation.h>

#include <MacGPGME/GPGDefines.h>
#include <MacGPGME/GPGKey.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


/*"
 * Returns a localized human readable string that describing the public
 * key algorithm value. Returns nil if value is not a valid public key
 * algorithm.
"*/
GPG_EXPORT NSString * GPGPublicKeyAlgorithmDescription(GPGPublicKeyAlgorithm value);


/*"
 * Returns a non-localized human readable string that describing the public
 * key algorithm value. Returns nil if value is not a valid public key
 * algorithm.
"*/
GPG_EXPORT NSString * GPGLocalizedPublicKeyAlgorithmDescription(GPGPublicKeyAlgorithm value);


/*"
 * Returns a localized human readable string that corresponds to the gcrypt input value
"*/
GPG_EXPORT NSString * GPGSymmetricKeyAlgorithmDescription(GPGSymmetricKeyAlgorithm value);


/*"
 * Returns a localized human readable string describing the hash algorithm
 * algo. Returns nil if value is not a valid hash algorithm.
"*/
GPG_EXPORT NSString * GPGLocalizedHashAlgorithmDescription(GPGHashAlgorithm value);


/*"
 * Returns a non-localized human readable string describing the hash algorithm
 * algo. This string can be used to output the name of the hash algorithm to
 * the user. Returns nil if value is not a valid hash algorithm.
"*/
GPG_EXPORT NSString * GPGHashAlgorithmDescription(GPGHashAlgorithm value);


/*"
 * Returns a localized human readable string that corresponds to the gcrypt input value
"*/
GPG_EXPORT NSString * GPGValidityDescription(GPGValidity value);


/*"
 * Returns a non-localized human readable string that corresponds to the protocol input value.
 * Returns nil if protocol is not valid.
"*/
GPG_EXPORT NSString * GPGProtocolDescription(GPGProtocol protocol);


/*"
 * Returns a localized human readable string that corresponds to the protocol input value.
 * Returns nil if protocol is not valid.
"*/
GPG_EXPORT NSString * GPGLocalizedProtocolDescription(GPGProtocol protocol);

#ifdef __cplusplus
}
#endif
#endif /* GPGPRETTYINFO_H */
