//
//  GPGSignature.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Sun Jul 14 2002.
//
//
//  Copyright (C) 2002 Mac GPG Project.
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

#ifndef GPGSIGNATURE_H
#define GPGSIGNATURE_H

#include <Foundation/Foundation.h>
#include <GPGME/GPGKey.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


/*"
 * The #GPGSignatureStatus type holds the result of a signature check,
 * or the combined result of all signatures. The following results are possible:
 * _{GPGSignatureStatusNone               No status.
 *                                        This status should not occur in normal operation.}
 * _{GPGSignatureStatusGood               The signature is valid.
 *                                        For the combined result this status means that
 *                                        all signatures are valid.}
 * _{GPGSignatureStatusBad                The signature is not valid.
 *                                        For the combined result this status means that
 *                                        all signatures are invalid.}
 * _{GPGSignatureStatusNoKey              The signature could not be checked due to a missing key.
 *                                        For the combined result this status means that
 *                                        all signatures could not be checked due to missing keys.}
 * _{GPGSignatureStatusNoSignature        This is not a signature.}
 * _{GPGSignatureStatusError              Due to some other error the check could not be done.}
 * _{GPGSignatureStatusDifferent          There is more than 1 signature and
 *                                        they have not the same status.}
 * _{GPGSignatureStatusGoodButExpired     The signature is valid but expired.
 *                                        For the combined result this status means that
 *                                        all signatures are valid and expired.}
 * _{GPGSignatureStatusGoodButKeyExpired  The signature is valid but the key used to
 *                                        verify the signature has expired. For the
 *                                        combined result this status means that all
 *                                        signatures are valid and all keys are expired.}
"*/
typedef enum {
    GPGSignatureStatusNone              = 0,
    GPGSignatureStatusGood              = 1,
    GPGSignatureStatusBad               = 2,
    GPGSignatureStatusNoKey             = 3,
    GPGSignatureStatusNoSignature       = 4,
    GPGSignatureStatusError             = 5,
    GPGSignatureStatusDifferent         = 6,
    GPGSignatureStatusGoodButExpired    = 7,
    GPGSignatureStatusGoodButKeyExpired = 8
} GPGSignatureStatus;


/*"
 * Mask values used in #{-summary}.
 * _{GPGSignatureSummaryValidMask             The signature is fully valid}
 * _{GPGSignatureSummaryGreenMask             The signature is good}
 * _{GPGSignatureSummaryRedMask               The signature is bad}
 * _{GPGSignatureSummaryKeyRevokedMask        One key has been revoked}
 * _{GPGSignatureSummaryKeyExpiredMask        One key has expired}
 * _{GPGSignatureSummarySignatureExpiredMask  The signature has expired}
 * _{GPGSignatureSummaryKeyMissingMask        Can't verify: key missing}
 * _{GPGSignatureSummaryCRLMissingMask        CRL not available}
 * _{GPGSignatureSummaryCRLTooOldMask         Available CRL is too old}
 * _{GPGSignatureSummaryBadPolicyMask         A policy was not met}
 * _{GPGSignatureSummarySystemErrorMask       A system error occured}
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


@interface GPGSignature : NSObject
{
    void		*_internalRepresentation;
    unsigned	_index;
}

- (NSString *) fingerprint;
- (GPGKey *) key;
- (NSString *) errorToken;
- (NSString *) suberrorToken;
- (NSCalendarDate *) creationDate;
- (NSCalendarDate *) expirationDate;
- (GPGValidity) validity;
- (NSString *) validityDescription;
- (GPGSignatureStatus) status;
- (GPGSignatureSummaryMask) summary;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGSIGNATURE_H */
