//
//  GPGPrettyInfo.h
//  GPGME
//
//  Created by Gordon Worley on Tue Jun 18 2002.
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

#ifndef GPGPRETTYINFO_H
#define GPGPRETTYINFO_H

#include <Foundation/Foundation.h>

#include <GPGME/GPGKey.h>
#include <GPGME/GPGRecipients.h>
#include <GPGME/GPGDefines.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif

GPG_EXPORT NSString * GPGPublicKeyAlgorithmDescription(GPGPublicKeyAlgorithm value);
GPG_EXPORT NSString * GPGSymmetricKeyAlgorithmDescription(GPGSymmetricKeyAlgorithm value);
GPG_EXPORT NSString * GPGHashAlgorithmDescription(GPGHashAlgorithm value);
GPG_EXPORT NSString * GPGValidityDescription(GPGValidity value);

#ifdef __cplusplus
}
#endif
#endif /* GPGPRETTYINFO_H */
