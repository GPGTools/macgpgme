//
//  GPGPrettyInfo.m
//  GPGME
//
//  Created by Gordon Worley on Tue Jun 18 2002.
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

#import "GPGPrettyInfo.h"
#import "LocalizableStrings.h"


NSString * GPGPublicKeyAlgorithmDescription(GPGPublicKeyAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;
    
    switch (value)	{
        case GPG_RSAAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGRSAAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_RSAEncryptOnlyAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGRSAEncryptOnlyAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_RSASignOnlyAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGRSASignOnlyAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_ElgamalEncryptOnlyAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGElgamalEncryptOnlyAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_DSAAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGDSAAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_EllipticCurveAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGEllipticCurveAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_ECDSAAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGECDSAAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_ElgamalAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGElgamalAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_DiffieHellmanAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGDiffieHellmanAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        default:
            return_value = NSLocalizedStringFromTableInBundle(GPGUnknownString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
    }

    return return_value;
}

NSString * GPGSymmetricKeyAlgorithmDescription(GPGSymetricKeyAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/

{
    NSString *return_value;

    switch (value)	{
        case GPG_NoAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGNoAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_IDEAAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGIDEAAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_TripleDESAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGTripleDESAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_CAST5Algorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGCAST5AlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_BlowfishAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGBlowfishAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_SAFER_SK128Algorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGSAFERSK128AlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_DES_SKAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGDESSKAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_AES128Algorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGAES128AlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_AES192Algorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGAES192AlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_AES256Algorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGAES256AlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_TwoFishAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGTwoFishAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_SkipjackAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGSkipjackAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_TwoFish_OldAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGTwoFishOldAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_DummyAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGDummyAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        default:
            return_value = NSLocalizedStringFromTableInBundle(GPGUnknownString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
    }

    return return_value;    
}

NSString * GPGHashAlgorithmDescription(GPGHashAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;

    switch (value)	{
        case GPG_MD5HashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGMD5HashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_SHA_1HashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGSHA1HashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_RIPE_MD160HashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGRIPEMD160HashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_DoubleWidthSHAHashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGDoubleWidthSHAHashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_MD2HashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGMD2HashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_TIGER192HashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGTIGER192HashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPG_HAVALHashAlgorithm:
            return_value = NSLocalizedStringFromTableInBundle(GPGHAVALHashAlgorithmString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        default:
            return_value = NSLocalizedStringFromTableInBundle(GPGUnknownString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
    }

    return return_value;    
}

NSString * GPGValidityDescription(GPGValidity value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;

    switch (value)	{
        case GPGValidityUndefined:
            return_value = NSLocalizedStringFromTableInBundle(GPGValidityUndefinedString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPGValidityNever:
            return_value = NSLocalizedStringFromTableInBundle(GPGValidityNeverString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPGValidityMarginal:
            return_value = NSLocalizedStringFromTableInBundle(GPGValidityMarginalString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPGValidityFull:
            return_value = NSLocalizedStringFromTableInBundle(GPGValidityFullString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        case GPGValidityUltimate:
            return_value = NSLocalizedStringFromTableInBundle(GPGValidityUltimateString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
        default:  //GPGValidityUnknown = 0; if it's something else I guess it's also unknown
            return_value = NSLocalizedStringFromTableInBundle(GPGUnknownString, nil, [NSBundle bundleForClass: [GPGObject class]], "");
            break;
    }
    
    return return_value;
}
