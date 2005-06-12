//
//  GPGSignature.h
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Sun Jul 14 2002.
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

#ifndef GPGSIGNATURE_H
#define GPGSIGNATURE_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGKey.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


/*"
 * Mask values used in #{-summary}.
 * _{GPGSignatureSummaryValidMask             The signature is fully valid.}
 * _{GPGSignatureSummaryGreenMask             The signature is good but one
 *                                            might want to display some extra
 *                                            information. Check the other
 *                                            bits.}
 * _{GPGSignatureSummaryRedMask               The signature is bad. It might
 *                                            be useful to check other bits
 *                                            and display more information,
 *                                            i.e. a revoked certificate might
 *                                            not render a signature invalid
 *                                            when the message was received
 *                                            prior to the cause for the
 *                                            revocation.}
 * _{GPGSignatureSummaryKeyRevokedMask        The key or at least one
 *                                            certificate has been revoked.}
 * _{GPGSignatureSummaryKeyExpiredMask        The key or one of the
 *                                            certificates has expired. It is
 *                                            probably a good idea to display
 *                                            the date of the expiration.}
 * _{GPGSignatureSummarySignatureExpiredMask  The signature has expired}
 * _{GPGSignatureSummaryKeyMissingMask        Can't verify due to a missing
 *                                            key or certificate.}
 * _{GPGSignatureSummaryCRLMissingMask        The CRL (or an equivalent
 *                                            mechanism) is not available.}
 * _{GPGSignatureSummaryCRLTooOldMask         Available CRL is too old.}
 * _{GPGSignatureSummaryBadPolicyMask         A policy requirement was not
 *                                            met.}
 * _{GPGSignatureSummarySystemErrorMask       A system error occured.}
"*/
typedef enum {
    GPGSignatureSummaryValidMask            = 0x0001,
    GPGSignatureSummaryGreenMask            = 0x0002,
    GPGSignatureSummaryRedMask              = 0x0004,
    GPGSignatureSummaryKeyRevokedMask       = 0x0010,
    GPGSignatureSummaryKeyExpiredMask       = 0x0020,
    GPGSignatureSummarySignatureExpiredMask = 0x0040,
    GPGSignatureSummaryKeyMissingMask       = 0x0080,
    GPGSignatureSummaryCRLMissingMask       = 0x0100,
    GPGSignatureSummaryCRLTooOldMask        = 0x0200,
    GPGSignatureSummaryBadPolicyMask        = 0x0400,
    GPGSignatureSummarySystemErrorMask      = 0x0800
}GPGSignatureSummaryMask;


@interface GPGSignature : NSObject <NSCopying>
{
    NSString				*_fingerprint;
    NSCalendarDate			*_creationDate;
    NSCalendarDate			*_expirationDate;
    GPGValidity				_validity;
    GPGError				_status;
    GPGSignatureSummaryMask	_summary;
    NSDictionary			*_notations;
    NSArray					*_policyURLs;
    GPGError				_validityError;
    BOOL					_wrongKeyUsage;
    GPGPublicKeyAlgorithm	_algorithm;
    GPGHashAlgorithm		_hashAlgorithm;
    unsigned int			_signatureClass;
}

/*"
 * Attributes
"*/
- (NSString *) fingerprint;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;
- (GPGValidity) validity;
- (GPGError) status;
- (GPGSignatureSummaryMask) summary;
- (GPGPublicKeyAlgorithm) algorithm;
- (GPGHashAlgorithm) hashAlgorithm;
- (unsigned int) signatureClass;

/*"
 * Notations
"*/
- (NSDictionary *) notations;
- (NSArray *) policyURLs;

/*"
 * Misc
"*/
- (GPGError) validityError;

- (BOOL) wrongKeyUsage;

/*"
 * Convenience methods
"*/
- (NSString *) validityDescription;
- (NSString *) algorithmDescription;
- (NSString *) hashAlgorithmDescription;
- (NSString *) formattedFingerprint;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGSIGNATURE_H */
