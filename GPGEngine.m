//
//  GPGEngine.m
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

#include <GPGME/GPGEngine.h>
#include <GPGME/GPGObject.h>
#include <GPGME/GPGPrettyInfo.h>
#include <GPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _engine	((gpgme_engine_info_t)_internalRepresentation)


@implementation GPGEngine
/*"
 * GPGME supports several cryptographic protocols, however, it does not
 * implement them. Rather it uses backends (also called engines) which
 * implement the protocol. GPGME uses inter-process communication to pass data
 * back and forth between the application and the backend, but the details of
 * the communication protocol and invocation of the backend is completely
 * hidden by the interface. All complexity is handled by GPGME. Where an
 * exchange of information between the application and the backend is
 * necessary, GPGME provides the necessary callback method hooks and further
 * interfaces.
"*/

+ (GPGError) checkVersionForProtocol:(GPGProtocol)protocol
/*"
 * Checks that the engine implementing the protocol protocol is installed
 * in the expected path and meets the version requirement of GPGME.
 *
 * This method returns #GPGErrorNoError if the engine
 * is available and an error whose code is #GPGErrorInvalidEngine if it is not.
"*/
{
    return gpgme_engine_check_version(protocol);
}

+ (NSString *) checkFrameworkVersion:(NSString *)requiredVersion
/*"
 * Checks that the version of the framework is at minimum the requested one
 * and returns the version string; returns nil if the condition is not met or
 * requiredVersion is not a valid version number. If requiredVersion is nil,
 * no check is done and the version string is simply returned.
 *
 * Note that this check is automatically performed before any GPGME 
 * object/function is used; it is called from #{+[GPGObject initialize]}.
"*/
{
    const char	*aCString;

    aCString = gpgme_check_version(requiredVersion == nil ? NULL:[requiredVersion UTF8String]); // statically allocated string or NULL

    return GPGStringFromChars(aCString);
}

+ (NSArray *) availableEngines
/*"
 * Returns an array of GPGEngine instances. Each instance describes one
 * configured backend.
"*/
{
    gpgme_engine_info_t	anEngine = NULL;
    gpgme_error_t		anError = gpgme_get_engine_info(&anEngine); // The memory for the info structures is allocated the first time this function is invoked, and must not be freed by the caller.
    NSMutableArray		*engines;

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    engines = [NSMutableArray arrayWithCapacity:2];
    while(anEngine != NULL){
        GPGEngine	*newEngine = [[GPGEngine alloc] initWithInternalRepresentation:anEngine];

        [engines addObject:newEngine];
        anEngine = anEngine->next;
        [newEngine release];
    }

    return engines;
}

- (GPGProtocol) engineProtocol
/*"
 * Returns the protocol for which the crypto engine is used. You can convert
 * this to a string with #{GPGProtocolDescription()} or
 * #{GPGLocalizedProtocolDescription()} for printing
"*/
{
    return _engine->protocol;
}

- (NSString *) executablePath
/*"
 * Returns a string holding the file name of the executable of the crypto
 * engine. Currently, it is never nil, but using nil is reserved for future
 * use, so always check before you use it.
"*/
{
    const char	*aCString = _engine->file_name;

    return GPGStringFromChars(aCString);
}

- (NSString *) version
/*"
 * This is a string containing the version number of the crypto engine. It
 * might be nil if the version number can not be determined, for example
 * because the executable doesn't exist or is invalid.
"*/
{
    const char	*aCString = _engine->version;

    return GPGStringFromChars(aCString);
}

- (NSString *) requestedVersion
/*"
 * Returns a string containing the minimum required version number of the
 * crypto engine for GPGME to work correctly. This is the version number that
 * #{+checkVersionForProtocol:} verifies against. Currently, it is never nil,
 * but using nil is reserved for future use, so always check before you use it.
"*/
{
    const char	*aCString = _engine->req_version;

    return GPGStringFromChars(aCString);
}

- (NSString *) debugDescription
{
    return [NSString stringWithFormat:@"<%@ %p> %@ %@ (%@), %@", NSStringFromClass([self class]), self, GPGProtocolDescription([self engineProtocol]), [self version], [self requestedVersion], [self executablePath]];
}

@end
