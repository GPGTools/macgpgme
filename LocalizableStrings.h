//
//  LocalizableStrings.h
//  GPGME
//
//  Created by Gordon Worley
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
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx>
//

#ifndef LOCALIZABLESTRINGS_H
#define LOCALIZABLESTRINGS_H

#include <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif

extern NSString * const GPGUnknownString;
extern NSString * const GPGValidityUndefinedString;
extern NSString * const GPGValidityNeverString;
extern NSString * const GPGValidityMarginalString;
extern NSString * const GPGValidityFullString;
extern NSString * const GPGValidityUltimateString;
extern NSString * const GPGMD5HashAlgorithmString;
extern NSString * const GPGSHA1HashAlgorithmString;
extern NSString * const GPGRIPEMD160HashAlgorithmString;
extern NSString * const GPGDoubleWidthSHAHashAlgorithmString;
extern NSString * const GPGMD2HashAlgorithmString;
extern NSString * const GPGTIGER192HashAlgorithmString;
extern NSString * const GPGHAVALHashAlgorithmString;
extern NSString * const GPGRSAAlgorithmString;
extern NSString * const GPGRSAEncryptOnlyAlgorithmString;
extern NSString * const GPGRSASignOnlyAlgorithmString;
extern NSString * const GPGElgamalEncryptOnlyAlgorithmString;
extern NSString * const GPGDSAAlgorithmString;
extern NSString * const GPGEllipticCurveAlgorithmString;
extern NSString * const GPGECDSAAlgorithmString;
extern NSString * const GPGElgamalAlgorithmString;
extern NSString * const GPGDiffieHellmanAlgorithmString;
extern NSString * const GPGNoAlgorithmString;
extern NSString * const GPGIDEAAlgorithmString;
extern NSString * const GPGTripleDESAlgorithmString;
extern NSString * const GPGCAST5AlgorithmString;
extern NSString * const GPGBlowfishAlgorithmString;
extern NSString * const GPGSAFERSK128AlgorithmString;
extern NSString * const GPGDESSKAlgorithmString;
extern NSString * const GPGAES128AlgorithmString;
extern NSString * const GPGAES192AlgorithmString;
extern NSString * const GPGAES256AlgorithmString;
extern NSString * const GPGTwoFishAlgorithmString;
extern NSString * const GPGSkipjackAlgorithmString;
extern NSString * const GPGTwoFishOldAlgorithmString;
extern NSString * const GPGDummyAlgorithmString;

#ifdef __cplusplus
}
#endif
#endif /* LOCALIZABLESTRINGS_H */
