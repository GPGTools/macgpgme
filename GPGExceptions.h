//
//  GPGExceptions.h
//  GPGME
//
//  Created by davelopper at users.sourceforge.net on Tue Aug 14 2001.
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

#ifndef GPGEXCEPTIONS_H
#define GPGEXCEPTIONS_H

#include <Foundation/Foundation.h>
#include <GPGME/GPGDefines.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSString;


/*"
 * The #GPGErrorCode type indicates the type of an error, or the reason why an
 * operation failed. Here are the most important ones:
 * _{GPGErrorEOF                          This value indicates the end of a
 *                                        list, buffer or file.}
 * _{GPGErrorNoError                      This value indicates success. The
 *                                        value of this error code is 0. Also,
 *                                        it is guaranteed that an error value
 *                                        made from the error code 0 will be 0
 *                                        itself (as a whole). This means that
 *                                        the error source information is lost
 *                                        for this error code, however, as
 *                                        this error code indicates that no
 *                                        error occured, this is generally not
 *                                        a problem. No #GPGException is raised
 *                                        with this value.}
 * _{GPGErrorGeneralError                 This value means that something went
 *                                        wrong, but either there is not enough
 *                                        information about the problem to
 *                                        return a more useful error value, or
 *                                        there is no separate error value for
 *                                        this type of problem.}
 * _{GPGError_ENOMEM                      This value means that an
 *                                        out-of-memory condition occurred.}
 * _{GPGError_E...                        System errors are mapped to
 *                                        GPGError_FOO where FOO is the symbol
 *                                        for the system error.}
 * _{GPGErrorInvalidValue                 This value means that some user
 *                                        provided data was out of range.
 *                                        This can also refer to objects. For
 *                                        example, if an empty #GPGData
 *                                        instance was expected, but one
 *                                        containing data was provided, this
 *                                        error value is returned.}
 * _{GPGErrorUnusablePublicKey            This value means that some
 *                                        recipients for a message were
 *                                        invalid.}
 * _{GPGErrorUnusableSecretKey            This value means that some signers
 *                                        were invalid.}
 * _{GPGErrorNoData                       This value means that a #GPGData
 *                                        instance which was expected to have
 *                                        content was found empty.}
 * _{GPGErrorConflict                     This value means that a conflict of
 *                                        some sort occurred.}
 * _{GPGErrorNotImplemented               This value indicates that the
 *                                        specific function (or operation) is
 *                                        not implemented. This error should
 *                                        never happen. It can only occur if
 *                                        you use certain values or
 *                                        configuration options which do not
 *                                        work, but for which we think that
 *                                        they should work at some later
 *                                        time.}
 * _{GPGErrorDecryptionFailed             This value indicates that a
 *                                        decryption operation was
 *                                        unsuccessful.}
 * _{GPGErrorBadPassphrase                This value means that the user did
 *                                        not provide a correct passphrase
 *                                        when requested.}
 * _{GPGErrorCancelled                    This value means that the operation
 *                                        was cancelled by user.}
 * _{GPGErrorInvalidEngine                This value means that the engine
 *                                        that implements the desired protocol
 *                                        is currently not available. This can
 *                                        either be because the sources were
 *                                        configured to exclude support for
 *                                        this engine, or because the engine
 *                                        is not installed properly.}
 * _{GPGErrorAmbiguousName                This value indicates that a user ID
 *                                        or other specifier did not specify a
 *                                        unique key.}
 * _{GPGErrorWrongKeyUsage                This value indicates that a key is
 *                                        not used appropriately.}
 * _{GPGErrorCertificateRevoked           This value indicates that a key
 *                                        signature was revoked.}
 * _{GPGErrorCertificateExpired           This value indicates that a key
 *                                        signature expired.}
 * _{GPGErrorNoCRLKnown                   This value indicates that no
 *                                        certificate revocation list is known
 *                                        for the certificate.}
 * _{GPGErrorNoPolicyMatch                This value indicates that a policy
 *                                        issue occured.}
 * _{GPGErrorNoSecretKey                  This value indicates that no secret
 *                                        key for the user ID is available.}
 * _{GPGErrorInvalidPassphrase            The passphrase is invalid, for
 *                                        example if it is in ISOLatin1
 *                                        although UTF-8 is expected}
 * _{GPGErrorMissingCertificate           This value indicates that a key
 *                                        could not be imported because the
 *                                        issuer certificate is missing.}
 * _{GPGErrorBadCertificateChain          This value indicates that a key
 *                                        could not be imported because its
 *                                        certificate chain is not good, for
 *                                        example it could be too long.}
 * _{GPGErrorUnsupportedAlgorithm         This value means a verification
 *                                        failed because the cryptographic
 *                                        algorithm is not supported by the
 *                                        crypto backend.}
 * _{GPGErrorBadSignature                 This value means a verification
 *                                        failed because the signature is
 *                                        bad.}
 * _{GPGErrorNoPublicKey                  This value means a verification
 *                                        failed because the public key is not
 *                                        available.}
 * _{GPGErrorUser1-GPGErrorUser16         These error codes are not used by
 *                                        any GnuPG component and can be
 *                                        freely used by other software.
 *                                        Applications using GPGME might use
 *                                        them to mark specific errors
 *                                        returned by callback handlers if no
 *                                        suitable error codes (including the
 *                                        system errors) for these errors
 *                                        exist already.}
"*/
typedef enum {
    GPGErrorNoError                      =     0,
    GPGErrorGeneralError                 =     1,
    GPGErrorUnknownPacket                =     2,
    GPGErrorUnknownVersion               =     3,
    GPGErrorInvalidPublicKeyAlgorithm    =     4,
    GPGErrorInvalidDigestAlgorithm       =     5,
    GPGErrorBadPublicKey                 =     6,
    GPGErrorBadSecretKey                 =     7,
    GPGErrorBadSignature                 =     8,
    GPGErrorNoPublicKey                  =     9,
    GPGErrorChecksumError                =    10,
    GPGErrorBadPassphrase                =    11,
    GPGErrorInvalidCipherAlgorithm       =    12,
    GPGErrorOpenKeyring                  =    13,
    GPGErrorInvalidPacket                =    14,
    GPGErrorInvalidArmor                 =    15,
    GPGErrorNoUserID                     =    16,
    GPGErrorNoSecretKey                  =    17,
    GPGErrorWrongSecretKey               =    18,
    GPGErrorBadSessionKey                =    19,
    GPGErrorUnknownCompressionAlgorithm  =    20,
    GPGErrorNoPrime                      =    21,
    GPGErrorNoEncodingMethod             =    22,
    GPGErrorNoEncryptionScheme           =    23,
    GPGErrorNoSignatureScheme            =    24,
    GPGErrorInvalidAttribute             =    25,
    GPGErrorNoValue                      =    26,
    GPGErrorNotFound                     =    27,
    GPGErrorValueNotFound                =    28,
    GPGErrorSyntax                       =    29,
    GPGErrorBadMPI                       =    30,
    GPGErrorInvalidPassphrase            =    31,
    GPGErrorSignatureClass               =    32,
    GPGErrorResourceLimit                =    33,
    GPGErrorInvalidKeyring               =    34,
    GPGErrorTrustDBError                 =    35,
    GPGErrorBadCertificate               =    36,
    GPGErrorInvalidUserID                =    37,
    GPGErrorUnexpected                   =    38,
    GPGErrorTimeConflict                 =    39,
    GPGErrorKeyServerError               =    40,
    GPGErrorWrongPublicKeyAlgorithm      =    41,
    GPGErrorTributeToDA                  =    42,
    GPGErrorWeakKey                      =    43,
    GPGErrorInvalidKeyLength             =    44,
    GPGErrorInvalidArgument              =    45,
    GPGErrorBadURI                       =    46,
    GPGErrorInvalidURI                   =    47,
    GPGErrorNetworkError                 =    48,
    GPGErrorUnknownHost                  =    49,
    GPGErrorSelfTestFailed               =    50,
    GPGErrorNotEncrypted                 =    51,
    GPGErrorNotProcessed                 =    52,
    GPGErrorUnusablePublicKey            =    53,
    GPGErrorUnusableSecretKey            =    54,
    GPGErrorInvalidValue                 =    55,
    GPGErrorBadCertificateChain          =    56,
    GPGErrorMissingCertificate           =    57,
    GPGErrorNoData                       =    58,
    GPGErrorBug                          =    59,
    GPGErrorNotSupported                 =    60,
    GPGErrorInvalidOperationCode         =    61,
    GPGErrorTimeout                      =    62,
    GPGErrorInternalError                =    63,
    GPGErrorEOFInGCrypt                  =    64,
    GPGErrorInvalidObject                =    65,
    GPGErrorObjectTooShort               =    66,
    GPGErrorObjectTooLarge               =    67,
    GPGErrorNoObject                     =    68,
    GPGErrorNotImplemented               =    69,
    GPGErrorConflict                     =    70,
    GPGErrorInvalidCipherMode            =    71,
    GPGErrorInvalidFlag                  =    72,
    GPGErrorInvalidHandle                =    73,
    GPGErrorTruncatedResult              =    74,
    GPGErrorIncompleteLine               =    75,
    GPGErrorInvalidResponse              =    76,
    GPGErrorNoAgent                      =    77,
    GPGErrorAgentError                   =    78,
    GPGErrorInvalidData                  =    79,
    GPGErrorAssuanServerFault            =    80,
    GPGErrorAssuanError                  =    81,
    GPGErrorInvalidSessionKey            =    82,
    GPGErrorInvalidSEXP                  =    83,
    GPGErrorUnsupportedAlgorithm         =    84,
    GPGErrorNoPINEntry                   =    85,
    GPGErrorPINEntryError                =    86,
    GPGErrorBadPIN                       =    87,
    GPGErrorInvalidName                  =    88,
    GPGErrorBadData                      =    89,
    GPGErrorInvalidParameter             =    90,
    GPGErrorWrongCard                    =    91, 
    GPGErrorNoDirManager                 =    92,
    GPGErrorDirManagerError              =    93,
    GPGErrorCertificateRevoked           =    94,
    GPGErrorNoCRLKnown                   =    95,
    GPGErrorCRLTooOld                    =    96,
    GPGErrorLineTooLong                  =    97,
    GPGErrorNotTrusted                   =    98,    
    GPGErrorCancelled                    =    99,
    GPGErrorBadCACertificate             =   100,
    GPGErrorCertificateExpired           =   101,
    GPGErrorCertificateTooYoung          =   102,
    GPGErrorUnsupportedCertificate       =   103,
    GPGErrorUnknownSEXP                  =   104,
    GPGErrorUnsupportedProtection        =   105,
    GPGErrorCorruptedProtection          =   106,
    GPGErrorAmbiguousName                =   107,
    GPGErrorCardError                    =   108,
    GPGErrorCardReset                    =   109,
    GPGErrorCardRemoved                  =   110,
    GPGErrorInvalidCard                  =   111,
    GPGErrorCardNotPresent               =   112,
    GPGErrorNoPKCS15Application          =   113,
    GPGErrorNotConfirmed                 =   114,
    GPGErrorConfigurationError           =   115,
    GPGErrorNoPolicyMatch                =   116,
    GPGErrorInvalidIndex                 =   117,
    GPGErrorInvalidID                    =   118,
    GPGErrorNoSCDaemon                   =   119,
    GPGErrorSCDaemonError                =   120,
    GPGErrorUnsupportedProtocol          =   121,
    GPGErrorBadPINMethod                 =   122,
    GPGErrorCardNotInitialized           =   123,
    GPGErrorUnsupportedOperation         =   124,
    GPGErrorWrongKeyUsage                =   125,
    GPGErrorNothingFound                 =   126,
    GPGErrorWrongBLOBType                =   127,
    GPGErrorMissingValue                 =   128,
    GPGErrorHardware                     =   129,
    GPGErrorPINBlocked                   =   130,
    GPGErrorUseConditions                =   131,
    GPGErrorPINNotSynced                 =   132,
    GPGErrorInvalidCRL                   =   133,
    GPGErrorBadBER                       =   134,
    GPGErrorInvalidBER                   =   135,
    GPGErrorElementNotFound              =   136,
    GPGErrorIdentifierNotFound           =   137,
    GPGErrorInvalidTag                   =   138,
    GPGErrorInvalidLength                =   139,
    GPGErrorInvalidKeyInfo               =   140,
    GPGErrorUnexpectedTag                =   141,
    GPGErrorNotDEREncoded                =   142,
    GPGErrorNoCMSObject                  =   143,
    GPGErrorInvalidCMSObject             =   144,
    GPGErrorUnknownCMSObject             =   145,
    GPGErrorUnsupportedCMSObject         =   146,
    GPGErrorUnsupportedEncoding          =   147,
    GPGErrorUnsupportedCMSVersion        =   148,
    GPGErrorUnknownAlgorithm             =   149,    
    GPGErrorInvalidEngine                =   150,
    GPGErrorPublicKeyNotTrusted          =   151,
    GPGErrorDecryptionFailed             =   152,
    GPGErrorKeyExpired                   =   153,
    GPGErrorSignatureExpired             =   154,
    GPGErrorEncodingProblem              =   155,
    GPGErrorInvalidState                 =   156,
    GPGErrorDuplicateValue               =   157,
    GPGErrorMissingAction                =   158,
    GPGErrorModuleNotFound               =   159,
    GPGErrorInvalidOIDString             =   160,
    GPGErrorInvalidTime                  =   161,
    GPGErrorInvalidCRLObject             =   162,
    GPGErrorUnsupportedCRLVersion        =   163,
    GPGErrorInvalidCertObject            =   164,
    GPGErrorUnknownName                  =   165,
    GPGErrorLocaleProblem                =   166,
    GPGErrorNotLocked                    =   167,
    GPGErrorProtocolViolation            =   168,
    GPGErrorInvalidMac                   =   169,
    GPGErrorInvalidRequest               =   170,

    GPGErrorBufferTooShort               =   200,
    GPGErrorSEXPInvalidLengthSpec        =   201,
    GPGErrorSEXPStringTooLong            =   202,
    GPGErrorSEXPUnmatchedParenthese      =   203,
    GPGErrorSEXPNotCanonical             =   204,
    GPGErrorSEXPBadCharacter             =   205,
    GPGErrorSEXPBadQuotation             =   206,
    GPGErrorSEXPZeroPrefix               =   207,
    GPGErrorSEXPNestedDisplayHint        =   208,
    GPGErrorSEXPUnmatchedDisplayHint     =   209,
    GPGErrorSEXPUnexpectedPunctuation    =   210,
    GPGErrorSEXPBadHexCharacter          =   211,
    GPGErrorSEXPOddHexNumbers            =   212,
    GPGErrorSEXPBadOctalCharacter        =   213,

    GPGErrorTruncatedKeyListing          =  1024,
    GPGErrorUser2                        =  1025,
    GPGErrorUser3                        =  1026,
    GPGErrorUser4                        =  1027,
    GPGErrorUser5                        =  1028,
    GPGErrorUser6                        =  1029,
    GPGErrorUser7                        =  1030,
    GPGErrorUser8                        =  1031,
    GPGErrorUser9                        =  1032,
    GPGErrorUser10                       =  1033,
    GPGErrorUser11                       =  1034,
    GPGErrorUser12                       =  1035,
    GPGErrorUser13                       =  1036,
    GPGErrorUser14                       =  1037,
    GPGErrorUser15                       =  1038,
    GPGErrorUser16                       =  1039,

    GPGErrorUnknownErrno                 = 16382,
    GPGErrorEOF                          = 16383,

    /* The following error codes are used to map system errors.  */
    GPGError_E2BIG                       = 16384,
    GPGError_EACCES                      = 16385,
    GPGError_EADDRINUSE                  = 16386,
    GPGError_EADDRNOTAVAIL               = 16387,
    GPGError_EADV                        = 16388,
    GPGError_EAFNOSUPPORT                = 16389,
    GPGError_EAGAIN                      = 16390,
    GPGError_EALREADY                    = 16391,
    GPGError_EAUTH                       = 16392,
    GPGError_EBACKGROUND                 = 16393,
    GPGError_EBADE                       = 16394,
    GPGError_EBADF                       = 16395,
    GPGError_EBADFD                      = 16396,
    GPGError_EBADMSG                     = 16397,
    GPGError_EBADR                       = 16398,
    GPGError_EBADRPC                     = 16399,
    GPGError_EBADRQC                     = 16400,
    GPGError_EBADSLT                     = 16401,
    GPGError_EBFONT                      = 16402,
    GPGError_EBUSY                       = 16403,
    GPGError_ECANCELLED                  = 16404,
    GPGError_ECHILD                      = 16405,
    GPGError_ECHRNG                      = 16406,
    GPGError_ECOMM                       = 16407,
    GPGError_ECONNABORTED                = 16408,
    GPGError_ECONNREFUSED                = 16409,
    GPGError_ECONNRESET                  = 16410,
    GPGError_ED                          = 16411,
    GPGError_EDEADLK                     = 16412,
    GPGError_EDEADLOCK                   = 16413,
    GPGError_EDESTADDRREQ                = 16414,
    GPGError_EDIED                       = 16415,
    GPGError_EDOM                        = 16416,
    GPGError_EDOTDOT                     = 16417,
    GPGError_EDQUOT                      = 16418,
    GPGError_EEXIST                      = 16419,
    GPGError_EFAULT                      = 16420,
    GPGError_EFBIG                       = 16421,
    GPGError_EFTYPE                      = 16422,
    GPGError_EGRATUITOUS                 = 16423,
    GPGError_EGREGIOUS                   = 16424,
    GPGError_EHOSTDOWN                   = 16425,
    GPGError_EHOSTUNREACH                = 16426,
    GPGError_EIDRM                       = 16427,
    GPGError_EIEIO                       = 16428,
    GPGError_EILSEQ                      = 16429,
    GPGError_EINPROGRESS                 = 16430,
    GPGError_EINTR                       = 16431,
    GPGError_EINVAL                      = 16432,
    GPGError_EIO                         = 16433,
    GPGError_EISCONN                     = 16434,
    GPGError_EISDIR                      = 16435,
    GPGError_EISNAM                      = 16436,
    GPGError_EL2HLT                      = 16437,
    GPGError_EL2NSYNC                    = 16438,
    GPGError_EL3HLT                      = 16439,
    GPGError_EL3RST                      = 16440,
    GPGError_ELIBACC                     = 16441,
    GPGError_ELIBBAD                     = 16442,
    GPGError_ELIBEXEC                    = 16443,
    GPGError_ELIBMAX                     = 16444,
    GPGError_ELIBSCN                     = 16445,
    GPGError_ELNRNG                      = 16446,
    GPGError_ELOOP                       = 16447,
    GPGError_EMEDIUMTYPE                 = 16448,
    GPGError_EMFILE                      = 16449,
    GPGError_EMLINK                      = 16450,
    GPGError_EMSGSIZE                    = 16451,
    GPGError_EMULTIHOP                   = 16452,
    GPGError_ENAMETOOLONG                = 16453,
    GPGError_ENAVAIL                     = 16454,
    GPGError_ENEEDAUTH                   = 16455,
    GPGError_ENETDOWN                    = 16456,
    GPGError_ENETRESET                   = 16457,
    GPGError_ENETUNREACH                 = 16458,
    GPGError_ENFILE                      = 16459,
    GPGError_ENOANO                      = 16460,
    GPGError_ENOBUFS                     = 16461,
    GPGError_ENOCSI                      = 16462,
    GPGError_ENODATA                     = 16463,
    GPGError_ENODEV                      = 16464,
    GPGError_ENOENT                      = 16465,
    GPGError_ENOEXEC                     = 16466,
    GPGError_ENOLCK                      = 16467,
    GPGError_ENOLINK                     = 16468,
    GPGError_ENOMEDIUM                   = 16469,
    GPGError_ENOMEM                      = 16470,
    GPGError_ENOMSG                      = 16471,
    GPGError_ENONET                      = 16472,
    GPGError_ENOPKG                      = 16473,
    GPGError_ENOPROTOOPT                 = 16474,
    GPGError_ENOSPC                      = 16475,
    GPGError_ENOSR                       = 16476,
    GPGError_ENOSTR                      = 16477,
    GPGError_ENOSYS                      = 16478,
    GPGError_ENOTBLK                     = 16479,
    GPGError_ENOTCONN                    = 16480,
    GPGError_ENOTDIR                     = 16481,
    GPGError_ENOTEMPTY                   = 16482,
    GPGError_ENOTNAM                     = 16483,
    GPGError_ENOTSOCK                    = 16484,
    GPGError_ENOTSUP                     = 16485,
    GPGError_ENOTTY                      = 16486,
    GPGError_ENOTUNIQ                    = 16487,
    GPGError_ENXIO                       = 16488,
    GPGError_EOPNOTSUPP                  = 16489,
    GPGError_EOVERFLOW                   = 16490,
    GPGError_EPERM                       = 16491,
    GPGError_EPFNOSUPPORT                = 16492,
    GPGError_EPIPE                       = 16493,
    GPGError_EPROCLIM                    = 16494,
    GPGError_EPROCUNAVAIL                = 16495,
    GPGError_EPROGMISMATCH               = 16496,
    GPGError_EPROGUNAVAIL                = 16497,
    GPGError_EPROTO                      = 16498,
    GPGError_EPROTONOSUPPORT             = 16499,
    GPGError_EPROTOTYPE                  = 16500,
    GPGError_ERANGE                      = 16501,
    GPGError_EREMCHG                     = 16502,
    GPGError_EREMOTE                     = 16503,
    GPGError_EREMOTEIO                   = 16504,
    GPGError_ERESTART                    = 16505,
    GPGError_EROFS                       = 16506,
    GPGError_ERPCMISMATCH                = 16507,
    GPGError_ESHUTDOWN                   = 16508,
    GPGError_ESOCKTNOSUPPORT             = 16509,
    GPGError_ESPIPE                      = 16510,
    GPGError_ESRCH                       = 16511,
    GPGError_ESRMNT                      = 16512,
    GPGError_ESTALE                      = 16513,
    GPGError_ESTRPIPE                    = 16514,
    GPGError_ETIME                       = 16515,
    GPGError_ETIMEDOUT                   = 16516,
    GPGError_ETOOMANYREFS                = 16517,
    GPGError_ETXTBSY                     = 16518,
    GPGError_EUCLEAN                     = 16519,
    GPGError_EUNATCH                     = 16520,
    GPGError_EUSERS                      = 16521,
    GPGError_EWOULDBLOCK                 = 16522,
    GPGError_EXDEV                       = 16523,
    GPGError_EXFULL                      = 16524,

    /* This is one more than the largest allowed entry.  */
    GPGError_CODE_DIM                    = 65536
} GPGErrorCode;


/*"
 * The #GPGErrorSource type defines the different sources of errors/exceptions
 * used in GPGME. The error source has not a precisely defined meaning.
 * Sometimes it is the place where the error happened, sometimes it is the
 * place where an error was encoded into an error value. Usually the error
 * source will give an indication to where to look for the problem. This is
 * not always true, but it is attempted to achieve this goal.
 * _{GPG_UnknownErrorSource         Unknown error source}
 * _{GPG_GCryptErrorSource          Error comes from C library %gcrypt, which
 *                                  is used by crypto engines to perform
 *                                  cryptographic operations}
 * _{GPG_GPGErrorSource             Error comes from %GnuPG, which is the
 *                                  crypto engine used for the OpenPGP
 *                                  protocol}
 * _{GPG_GPGSMErrorSource           Error comes from %GPGSM, which is the
 *                                  crypto engine used for the CMS protocol}
 * _{GPG_GPGAgentErrorSource        Error comes from %gpg-agent, which is used
 *                                  by crypto engines to perform operations
 *                                  with the secret key}
 * _{GPG_PINEntryErrorSource        Error comes from %pinentry, which is used
 *                                  by %gpg-agent to query the passphrase to
 *                                  unlock a secret key}
 * _{GPG_SCDErrorSource             Error comes from the %{SmartCard Daemon},
 *                                  which is used by %gpg-agent to delegate
 *                                  operations with the secret key to a
 *                                  %SmartCard}
 * _{GPG_GPGMELibErrorSource        Error comes from C library %gpgme}
 * _{GPG_KeyBoxErrorSource          Error comes from %libkbx, a library used
 *                                  by the crypto engines to manage local
 *                                  key-rings}
 * _{GPG_KSBAErrorSource            Error comes from C library %libksba}
 * _{GPG_DirMngrErrorSource         Error comes from %DirMngr}
 * _{GPG_GSTIErrorSource            Error comes from %GSTI}
 * _{GPG_GPGMEFrameworkErrorSource  Error comes from GPGME framework}
 * _{GPG_User2ErrorSource           (reserved)}
 * _{GPG_User3ErrorSource           (reserved)}
 * _{GPG_User4ErrorSource           (reserved)}
 * Any other value smaller than 256 can be used for your own purpose.
"*/
typedef enum {
    GPG_UnknownErrorSource         =  0,
    GPG_GCryptErrorSource          =  1,
    GPG_GPGErrorSource             =  2,
    GPG_GPGSMErrorSource           =  3,
    GPG_GPGAgentErrorSource        =  4,
    GPG_PINEntryErrorSource        =  5,
    GPG_SCDErrorSource             =  6,
    GPG_GPGMELibErrorSource        =  7,
    GPG_KeyBoxErrorSource          =  8,
    GPG_KSBAErrorSource            =  9,
    GPG_DirMngrErrorSource         = 10,
    GPG_GSTIErrorSource            = 11,
    GPG_GPGMEFrameworkErrorSource  = 32,
    GPG_User2ErrorSource           = 33,
    GPG_User3ErrorSource           = 34,
    GPG_User4ErrorSource           = 35
}GPGErrorSource;


/*"
 * An error value like this has always two components, an error code and an
 * error source. Both together form the error value.
 *
 * Thus, the error value can not be directly compared against an error code,
 * but the accessor functions #{GPGErrorSourceFromError()} and
 * #{GPGErrorCodeFromError()} must be used. However, it is guaranteed that
 * only 0 is used to indicate success (GPGErrorNoError), and that in this case
 * all other parts of the error value are set to 0, too.
 *
 * Note that in GPGME, the error source is used purely for diagnostical
 * purposes. Only the error code should be checked to test for a certain
 * outcome of a function. The manual only documents the error code part of an
 * error value. The error source is left unspecified and might be anything.
"*/
typedef unsigned int	GPGError;

/*"
 * Returns the (yet unlocalized) description of the error value (code).
 * This string can be used to output a diagnostic message to the user.
"*/
GPG_EXPORT NSString	*GPGErrorDescription(GPGError error);


/*"
 * Returns the (yet unlocalized) name of the source of the error.
 * This string can be used to output a diagnostic message to the user.
"*/
GPG_EXPORT NSString *GPGErrorSourceDescription(GPGErrorSource errorSource);

/*"
 * Returns the GPGErrorCode component of the error value err. This function
 * must be used to extract the error code from an error value in order to
 * compare it with the GPGError* error code values.
"*/
GPG_EXPORT GPGErrorCode GPGErrorCodeFromError(GPGError err);

/*"
 * Returns the GPGErrorSource component of the error value err. This function
 * must be used to extract the error source from an error value in order to
 * compare it with the GPG_*Source error source values.
"*/
GPG_EXPORT GPGErrorSource GPGErrorSourceFromError(GPGError err);

/*"
 * Returns the error value consisting of the error source src and the error
 * code cde.
 *
 * This function can be used in callback methods to construct an error value
 * to return it to the framework.
"*/
GPG_EXPORT GPGError GPGMakeError(GPGErrorSource src, GPGErrorCode cde);

/*"
 * The function #{GPGMakeErrorFromErrno()} is like #{GPGMakeError()}, but it
 * takes a system error like errno instead of a #GPGErrorCode error code.
"*/
GPG_EXPORT GPGError GPGMakeErrorFromErrno(GPGErrorSource src, int cde);

/*"
 * A #GPGException can be raised by nearly any GPGME call...
 *
 * Reason: description of #GPGError.
 *
 * UserInfo:
 * _{GPGErrorKey  		     A #NSNumber containing a #GPGError value}
 * _{GPGContextKey    		 The #GPGContext which terminated with an error;
 *                           used by #{+[GPGContext waitOnAnyRequest:]} and
 *                           for errors on asynchronous operations}
 * _{GPGAdditionalReasonKey  An additional unlocalized error message;
 *                           optional}
"*/
GPG_EXPORT NSString	* const GPGException;
GPG_EXPORT NSString	* const GPGErrorKey;
GPG_EXPORT NSString * const	GPGAdditionalReasonKey;


@interface NSException(GPGExceptions)
+ (NSException *) exceptionWithGPGError:(GPGError)error userInfo:(NSDictionary *)userInfo;
@end

#ifdef __cplusplus
}
#endif
#endif /* GPGEXCEPTIONS_H */
