//
//  GPGEngine.h
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

#ifndef GPGENGINE_H
#define GPGENGINE_H

#include <MacGPGME/GPGObject.h>
#include <MacGPGME/GPGExceptions.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSString;
@class NSArray;
@class GPGContext;


/*"
 * The #GPGProtocol type specifies the set of possible protocol values that
 * are supported by MacGPGME. The following protocols are supported:
 * _{GPGOpenPGPProtocol  Default protocol. OpenPGP is implemented by GnuPG,
 *                       the GNU Privacy Guard. This is the first protocol
 *                       that was supported by MacGPGME.}
 * _{GPGCMSProtocol      CMS (Cryptographic Message Syntax) is implemented by
 *                       GpgSM, the S/MIME implementation for GnuPG.
 *                       #CAUTION: currently unsupported on MacOS X.}
"*/
typedef enum {
    GPGOpenPGPProtocol = 0,
    GPGCMSProtocol     = 1
} GPGProtocol;


@interface GPGEngine : GPGObject /*"NSObject"*/
{
    GPGContext  *_context; // Not retained
}

+ (GPGError) checkVersionForProtocol:(GPGProtocol)protocol;
+ (NSString *) checkFrameworkVersion:(NSString *)requiredVersion;
+ (NSString *) defaultHomeDirectoryForProtocol:(GPGProtocol)protocol;

+ (NSArray *) availableEngines;
+ (GPGEngine *) engineForProtocol:(GPGProtocol)protocol;

- (GPGProtocol) engineProtocol;
- (NSString *) version;
- (NSString *) requestedVersion;

- (NSString *) executablePath;
- (void) setExecutablePath:(NSString *)executablePath;

- (NSString *) homeDirectory;
- (void) setHomeDirectory:(NSString *)homeDirectory;

@end

#ifdef __cplusplus
}
#endif
#endif /* GPGENGINE_H */
