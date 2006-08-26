//
//  GPGEngine.m
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2006 Mac GPG Project.
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

+ (BOOL) needsPointerUniquing
{
    return YES;
}

+ (GPGError) checkVersionForProtocol:(GPGProtocol)protocol
{
    return gpgme_engine_check_version(protocol);
}

+ (NSString *) checkFrameworkVersion:(NSString *)requiredVersion
{
    const char	*aCString;

    aCString = gpgme_check_version(requiredVersion == nil ? NULL:[requiredVersion UTF8String]); // statically allocated string or NULL

    return GPGStringFromChars(aCString);
}

+ (NSArray *) availableEngines
{
    gpgme_engine_info_t	anEngine = NULL;
    gpgme_error_t		anError = gpgme_get_engine_info(&anEngine); // The memory for the info structures is allocated the first time this function is invoked, and must not be freed by the caller.

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return [self enginesFromEngineInfo:anEngine context:nil];
}

+ (GPGEngine *) engineForProtocol:(GPGProtocol)protocol
{
    NSEnumerator    *engineEnum = [[self availableEngines] objectEnumerator];
    GPGEngine       *anEngine;
    
    while((anEngine = [engineEnum nextObject]) != nil)
        if([anEngine engineProtocol] == protocol)
            return anEngine;

    return nil;
}

+ (NSString *) defaultHomeDirectoryForProtocol:(GPGProtocol)protocol
{
    static NSMutableDictionary *defaultHomeDirectoryPerProtocol = nil;
    NSNumber                    *aProtocol = [NSNumber numberWithInt:protocol];
    
    if(protocol != GPGOpenPGPProtocol)
        [[NSException exceptionWithGPGError:gpgme_err_make(GPG_MacGPGMEFrameworkErrorSource, GPGErrorNotImplemented) userInfo:nil] raise];

    if(defaultHomeDirectoryPerProtocol == nil){
        NSString    *gnupgHome = [[[NSProcessInfo processInfo] environment] objectForKey:@"GNUPGHOME"];
        NSString    *defaultHomeDirectory;
        
        defaultHomeDirectoryPerProtocol = [[NSMutableDictionary alloc] initWithCapacity:2];
        if(gnupgHome != nil)
            defaultHomeDirectory = gnupgHome;
        else
            defaultHomeDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@".gnupg"];
        [defaultHomeDirectoryPerProtocol setObject:defaultHomeDirectory forKey:aProtocol];
    }

    return [defaultHomeDirectoryPerProtocol objectForKey:aProtocol];
}

- (GPGProtocol) engineProtocol
{
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");

    return _engine->protocol;
}

- (NSString *) executablePath
{
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");

    return GPGStringFromChars(_engine->file_name);
}

- (void) setExecutablePath:(NSString *)executablePath
{
    NSParameterAssert(executablePath != nil);
    
    if(![[self executablePath] isEqualToString:executablePath]){
        const char      *aCString = [executablePath fileSystemRepresentation];
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
        
        // Calling gpgme_(ctx_)set_engine_info() will retrieve engine version. If NULL, engine
        // has not been found or is invalid.
        if([self version] == nil)
            [[NSException exceptionWithGPGError:gpgme_err_make(GPG_MacGPGMEFrameworkErrorSource, GPGErrorInvalidEngine) userInfo:nil] raise];
    }
}

- (NSString *) version
{
    const char	*aCString;

    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->version;

    return GPGStringFromChars(aCString);
}

- (NSString *) requestedVersion
{
    const char	*aCString;

    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->req_version;

    return GPGStringFromChars(aCString);
}

- (NSString *) homeDirectory
{
    const char	*aCString;
    
    NSAssert(_context != INVALID_CONTEXT, @"### GPGEngine instance was associated to a GPGContext that has been freed.");
    aCString = _engine->home_dir;

    return GPGStringFromChars(aCString);
}

- (void) setHomeDirectory:(NSString *)homeDirectory
{
    NSString    *myHomeDirectory = [self homeDirectory];
    
    if(myHomeDirectory != homeDirectory && ![myHomeDirectory isEqualToString:homeDirectory]){
        const char      *aCString = [homeDirectory fileSystemRepresentation];
        gpgme_error_t   anError;
        const char      *aPathCString = [[self executablePath] fileSystemRepresentation]; // Due to a bug in gpgme 1.1, we cannot pass the same pointer already in engine; we need to pass a copy of it. Reported to gpgme people.
        
        // different implementation when default or context's
        if(_context)
            anError = gpgme_ctx_set_engine_info([_context gpgmeContext], [self engineProtocol], aPathCString, aCString); // Will duplicate strings
        else
            anError = gpgme_set_engine_info([self engineProtocol], aPathCString, aCString); // Will duplicate strings
        
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
        return [NSString stringWithFormat:@"<%@ %p> %@ (min. %@), %@ (%@), %@ - %@", NSStringFromClass([self class]), self, GPGProtocolDescription([self engineProtocol]), [self requestedVersion], [self executablePath], [self version], [self homeDirectory], (_context != nil ? [_context description] : @"global")];
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
    GPGProtocol         myProtocol = [self engineProtocol];
    gpgme_engine_info_t anEngineInfo;

    anEngineInfo = gpgme_ctx_get_engine_info([_context gpgmeContext]);
    while(anEngineInfo != NULL){
        if(anEngineInfo->protocol == myProtocol)
            break;
        anEngineInfo = anEngineInfo->next;
    }
    NSAssert1(anEngineInfo != NULL, @"### Unable to refresh engine for protocol %@", GPGProtocolDescription(myProtocol));
    [[[self class] pointerUniquingTableLock] lock];
    [self unregisterUniquePointer];
    _internalRepresentation = anEngineInfo;
    [self registerUniquePointer];
    [[[self class] pointerUniquingTableLock] unlock];
}

@end
