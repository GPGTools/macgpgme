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

/*"
 * NOTE:
 * These functions require that the contesnts of Localizable.string in GPGME be
 * copied into your application.
"*/

NSString * GPGPrettyPublicKeyAlgorithm(GPGPublicKeyAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;
    
    switch (value)	{
        case GPG_RSAAlgorithm:
            return_value = NSLocalizedString(GPGRSAAlgorithmString, GPGRSAAlgorithmString);
            break;
        case GPG_RSAEncryptOnlyAlgorithm:
            return_value = NSLocalizedString(GPGRSAEncryptOnlyAlgorithmString, GPGRSAEncryptOnlyAlgorithmString);
            break;
        case GPG_RSASignOnlyAlgorithm:
            return_value = NSLocalizedString(GPGRSASignOnlyAlgorithmString, GPGRSASignOnlyAlgorithmString);
            break;
        case GPG_ElgamalEncryptOnlyAlgorithm:
            return_value = NSLocalizedString(GPGElgamalEncryptOnlyAlgorithmString, GPGElgamalEncryptOnlyAlgorithmString);
            break;
        case GPG_DSAAlgorithm:
            return_value = NSLocalizedString(GPGDSAAlgorithmString, GPGDSAAlgorithmString);
            break;
        case GPG_EllipticCurveAlgorithm:
            return_value = NSLocalizedString(GPGEllipticCurveAlgorithmString, GPGEllipticCurveAlgorithmString);
            break;
        case GPG_ECDSAAlgorithm:
            return_value = NSLocalizedString(GPGECDSAAlgorithmString, GPGECDSAAlgorithmString);
            break;
        case GPG_ElgamalAlgorithm:
            return_value = NSLocalizedString(GPGElgamalAlgorithmString, GPGElgamalAlgorithmString);
            break;
        case GPG_DiffieHellmanAlgorithm:
            return_value = NSLocalizedString(GPGDiffieHellmanAlgorithmString, GPGDiffieHellmanAlgorithmString);
            break;
        default:
            return_value = NSLocalizedString(GPGUnknownString, GPGUnknownString);
            break;
    }

    return return_value;
}

NSString * GPGPrettySymmetricKeyAlgorithm(GPGSymetricKeyAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/

{
    NSString *return_value;

    switch (value)	{
        case GPG_NoAlgorithm:
            return_value = NSLocalizedString(GPGNoAlgorithmString, GPGNoAlgorithmString);
            break;
        case GPG_IDEAAlgorithm:
            return_value = NSLocalizedString(GPGIDEAAlgorithmString, GPGIDEAAlgorithmString);
            break;
        case GPG_TripleDESAlgorithm:
            return_value = NSLocalizedString(GPGTripleDESAlgorithmString, GPGTripleDESAlgorithmString);
            break;
        case GPG_CAST5Algorithm:
            return_value = NSLocalizedString(GPGCAST5AlgorithmString, GPGCAST5AlgorithmString);
            break;
        case GPG_BlowfishAlgorithm:
            return_value = NSLocalizedString(GPGBlowfishAlgorithmString, GPGBlowfishAlgorithmString);
            break;
        case GPG_SAFER_SK128Algorithm:
            return_value = NSLocalizedString(GPGSAFERSK128AlgorithmString, GPGSAFERSK128AlgorithmString);
            break;
        case GPG_DES_SKAlgorithm:
            return_value = NSLocalizedString(GPGDESSKAlgorithmString, GPGDESSKAlgorithmString);
            break;
        case GPG_AES128Algorithm:
            return_value = NSLocalizedString(GPGAES128AlgorithmString, GPGAES128AlgorithmString);
            break;
        case GPG_AES192Algorithm:
            return_value = NSLocalizedString(GPGAES192AlgorithmString, GPGAES192AlgorithmString);
            break;
        case GPG_AES256Algorithm:
            return_value = NSLocalizedString(GPGAES256AlgorithmString, GPGAES256AlgorithmString);
            break;
        case GPG_TwoFishAlgorithm:
            return_value = NSLocalizedString(GPGTwoFishAlgorithmString, GPGTwoFishAlgorithmString);
            break;
        case GPG_SkipjackAlgorithm:
            return_value = NSLocalizedString(GPGSkipjackAlgorithmString, GPGSkipjackAlgorithmString);
            break;
        case GPG_TwoFish_OldAlgorithm:
            return_value = NSLocalizedString(GPGTwoFishOldAlgorithmString, GPGTwoFishOldAlgorithmString);
            break;
        case GPG_DummyAlgorithm:
            return_value = NSLocalizedString(GPGDummyAlgorithmString, GPGDummyAlgorithmString);
            break;
        default:
            return_value = NSLocalizedString(GPGUnknownString, GPGUnknownString);
            break;
    }

    return return_value;    
}

NSString * GPGPrettyHashAlgorithm(GPGHashAlgorithm value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;

    switch (value)	{
        case GPG_MD5HashAlgorithm:
            return_value = NSLocalizedString(GPGMD5HashAlgorithmString, GPGMD5HashAlgorithmString);
            break;
        case GPG_SHA_1HashAlgorithm:
            return_value = NSLocalizedString(GPGSHA1HashAlgorithmString, GPGSHA1HashAlgorithmString);
            break;
        case GPG_RIPE_MD160HashAlgorithm:
            return_value = NSLocalizedString(GPGRIPEMD160HashAlgorithmString, GPGRIPEMD160HashAlgorithmString);
            break;
        case GPG_DoubleWidthSHAHashAlgorithm:
            return_value = NSLocalizedString(GPGDoubleWidthSHAHashAlgorithmString, GPGDoubleWidthSHAHashAlgorithmString);
            break;
        case GPG_MD2HashAlgorithm:
            return_value = NSLocalizedString(GPGMD2HashAlgorithmString, GPGMD2HashAlgorithmString);
            break;
        case GPG_TIGER192HashAlgorithm:
            return_value = NSLocalizedString(GPGTIGER192HashAlgorithmString, GPGTIGER192HashAlgorithmString);
            break;
        case GPG_HAVALHashAlgorithm:
            return_value = NSLocalizedString(GPGHAVALHashAlgorithmString, GPGHAVALHashAlgorithmString);
            break;
        default:
            return_value = NSLocalizedString(GPGUnknownString, GPGUnknownString);
            break;
    }

    return return_value;    
}

NSString * GPGPrettyValidity(GPGValidity value)
/*"
 * Returns a human readable string that corresponds to the gcrypt input value
"*/
{
    NSString *return_value;

    switch (value)	{
        case GPGValidityUndefined:
            return_value = NSLocalizedString(GPGValidityUndefinedString, GPGValidityUndefinedString);
            break;
        case GPGValidityNever:
            return_value = NSLocalizedString(GPGValidityNeverString, GPGValidityNeverString);
            break;
        case GPGValidityMarginal:
            return_value = NSLocalizedString(GPGValidityMarginalString, GPGValidityMarginalString);
            break;
        case GPGValidityFull:
            return_value = NSLocalizedString(GPGValidityFullString, GPGValidityFullString);
            break;
        case GPGValidityUltimate:
            return_value = NSLocalizedString(GPGValidityUltimateString, GPGValidityUltimateString);
            break;
        default:  //GPGValidityUnknown = 0; if it's something else I guess it's also unknown
            return_value = NSLocalizedString(GPGUnknownString, GPGUnknownString);
            break;
    }
    
    return return_value;
}