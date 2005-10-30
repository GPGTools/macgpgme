//
//  GPGEngine.m
//  MacGPGME
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

#include <MacGPGME/GPGEngine.h>
#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGPrettyInfo.h>
#include <MacGPGME/GPGContext.h>
#include <MacGPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _engine ((gpgme_engine_info_t)_internalRepresentation)
#define INVALID_CONTEXT ((GPGContext *)-1)


@implementation GPGEngine
/*"
 * MacGPGME supports several cryptographic protocols, however, it does not
 * implement them. Rather it uses backends (also called engines) which
 * implement the protocol. MacGPGME uses inter-process communication to pass
 * data back and forth between the application and the backend, but the details
 * of the communication protocol and invocation of the backend is completely
 * hidden by the interface. All complexity is handled by MacGPGME. Where an
 * exchange of information between the application and the backend is
 * necessary, MacGPGME provides the necessary callback method hooks and further
 * interfaces.
 *
 * You can modify some parameters of the engines, like their executable path and
 * their home directory. This can be done either on the default engines, or the
 * engines proper to a GPGContext (see -[GPGContext engine]).
"*/

+ (GPGError) checkVersionForProtocol:(GPGProtocol)protocol
/*"
 * Checks that the engine implementing the protocol protocol is installed
 * in the expected path and meets the version requirement of MacGPGME.
 *
 * This method returns #GPGErrorNoError if the engine
 * is available and an error whose code is #GPGErrorInvalidEngine if it is not.
"*/
{
#warning This method does not work correctly in 1.1 when you change the default executable path!
    return gpgme_engine_check_version(protocol);
}

+ (NSString *) checkFrameworkVersion:(NSString *)requiredVersion
/*"
 * Checks that the version of the framework is at minimum the requested one
 * and returns the version string; returns nil if the condition is not met or
 * requiredVersion is not a valid version number. If requiredVersion is nil,
 * no check is done and the version string is simply returned.
 *
 * Note that this check is automatically performed before any MacGPGME 
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
#warning FIXME Should unique instance on pointer, in this case
    gpgme_engine_info_t	anEngine = NULL;
    gpgme_error_t		anError = gpgme_get_engine_info(&anEngine); // The memory for the info structures is allocated the first time this function is invoked, and must not be freed by the caller.

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return [self enginesFromEngineInfo:anEngine context:nil];
}

+ (NSString *) defaultHomeDirectory
/*"
 * Returns the default home directory (constant).
"*/
{
    static NSString *defaultHomeDirectory = nil;
    
#warning VERIFY
    if(defaultHomeDirectory == nil){
        NSString    *gnupgHome = [[[NSProcessInfo processInfo] environment] objectForKey:@"GNUPGHOME"];
        
        if(gnupgHome != nil)
            defaultHomeDirectory = [gnupgHome copy];
        else
            defaultHomeDirectory = [[NSHomeDirectory() stringByAppendingString:@".gnupg"] copy];
    }

    return defaultHomeDirectory;
}

- (GPGProtocol) engineProtocol
/*"
 * Returns the protocol for which the crypto engine is used. You can convert
 * this to a string with #{GPGProtocolDescription()} or
 * #{GPGLocalizedProtocolDescription()} for printing
"*/
{
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");

    return _engine->protocol;
}

- (NSString *) executablePath
/*"
 * Returns a string holding the file name of the executable of the crypto
 * engine. Currently, it is never nil, but using nil is reserved for future
 * use, so always check before you use it.
"*/
{
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");

    return GPGStringFromChars(_engine->file_name);
}

- (void) setExecutablePath:(NSString *)executablePath
/*"
 * Sets the path to the executable of the crypto engine. Currently may never be
 * nil.
"*/
{
#warning Verify
    NSParameterAssert(executablePath != nil);
    
    if(![[self executablePath] isEqualToString:executablePath]){
        const char      *aCString = [executablePath UTF8String];
        gpgme_error_t   anError;        
        
        // Different implementation when default or context's
        if(_context != nil)
            anError = gpgme_ctx_set_engine_info([_context gpgmeContext], [self engineProtocol], aCString, _engine->home_dir); // Will duplicate strings
        else
            anError = gpgme_set_engine_info([self engineProtocol], aCString, _engine->home_dir);
        
        if(anError != GPGErrorNoError)
            [[NSException exceptionWithGPGError:anError userInfo:(_context != nil ? [NSDictionary dictionaryWithObject:_context forKey:GPGContextKey] : nil)] raise];
        
        if(_context != nil){
            // Previous gpgme_engine_info_t struct is now invalid; we need to retrieve new one
            [self reloadContextEngineInfo];
        }
    }
}

- (NSString *) version
/*"
 * This is a string containing the version number of the crypto engine. It
 * might be nil if the version number can not be determined, for example
 * because the executable doesn't exist or is invalid.
"*/
{
    const char	*aCString;

    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->version;

    return GPGStringFromChars(aCString);
}

- (NSString *) requestedVersion
/*"
 * Returns a string containing the minimum required version number of the
 * crypto engine for MacGPGME to work correctly. This is the version number that
 * #{+checkVersionForProtocol:} verifies against. Currently, it is never nil,
 * but using nil is reserved for future use, so always check before you use it.
"*/
{
    const char	*aCString;

    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->req_version;

    return GPGStringFromChars(aCString);
}

- (NSString *) homeDirectory
/*"
 * Returns the directory name of the crypto engine's configuration directory. If
 * it is nil, then the default directory is used, i.e. $HOME/.gnupg for the 
 * OpenPGP engine.
"*/
{
    const char	*aCString;
    
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->home_dir;

    return GPGStringFromChars(aCString);
}

- (void) setHomeDirectory:(NSString *)homeDirectory
/*"
 * Sets the directory name of the crypto engine's configuration directory. If it
 * is nil, then the default directory is used, i.e. $HOME/.gnupg for the OpenPGP
 * engine.
"*/
{
    NSString    *myHomeDirectory = [self homeDirectory];
    
#warning Verify    
    if(myHomeDirectory != homeDirectory && ![myHomeDirectory isEqualToString:homeDirectory]){
        const char      *aCString = [homeDirectory UTF8String];
        gpgme_error_t   anError;
        
        // different implementation when default or context's
        if(_context)
            anError = gpgme_ctx_set_engine_info([_context gpgmeContext], [self engineProtocol], _engine->file_name, aCString); // Will duplicate strings
        else
            anError = gpgme_set_engine_info([self engineProtocol], _engine->file_name, aCString); // Will duplicate strings
        
        if(anError != GPGErrorNoError)
            [[NSException exceptionWithGPGError:anError userInfo:(_context != nil ? [NSDictionary dictionaryWithObject:_context forKey:GPGContextKey] : nil)] raise];
        
        if(_context != nil){
            // Previous gpgme_engine_info_t struct is now invalid; we need to retrieve new one
            [self reloadContextEngineInfo];
        }
    }
}

- (NSString *) debugDescription
{
    if(_context == INVALID_CONTEXT)
        return [NSString stringWithFormat:@"<%@ %p> [freed context]", NSStringFromClass([self class]), self];
    else
        return [NSString stringWithFormat:@"<%@ %p> %@ (min. %@), %@ (%@), %@ - %@", NSStringFromClass([self class]), self, GPGProtocolDescription([self engineProtocol]), [self requestedVersion], [self executablePath], [self version], [self homeDirectory], (_context != nil ? _context : @"global")];
}

@end

@implementation GPGEngine(GPGInternals)

+ (NSArray *) enginesFromEngineInfo:(gpgme_engine_info_t)engineInfo context:(GPGContext *)context
{
    NSMutableArray  *engines = [NSMutableArray arrayWithCapacity:2];
    
    while(engineInfo != NULL){
        GPGEngine	*newEngine = [[GPGEngine alloc] initWithInternalRepresentation:engineInfo];
        
        [engines addObject:newEngine];
        [newEngine setContext:context];
        engineInfo = engineInfo->next;
        [newEngine release];
    }
    
    return engines;
}

- (void) setContext:(GPGContext *)context
{
    _context = context; // Not retained
}

- (void) invalidateContext
{
    [self setContext:INVALID_CONTEXT];
}

- (void) reloadContextEngineInfo
{
    GPGProtocol myProtocol = [self engineProtocol];

    // For the moment, we don't unique GPGEngines according to their _internalRepresentation pointer
    // that's why we simply change pointer value.
    _internalRepresentation = gpgme_ctx_get_engine_info([_context gpgmeContext]);
    while(_internalRepresentation != NULL){
        if(_engine->protocol == myProtocol)
            break;
        _internalRepresentation = _engine->next;
    }
    NSAssert1(_engine != NULL, @"### Unable to refresh engine for protocol %@", GPGProtocolDescription(myProtocol));
}

@end
