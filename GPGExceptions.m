//
//  GPGExceptions.m
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2003 Mac GPG Project.
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

#include <GPGME/GPGExceptions.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


NSString	* const GPGException = @"GPGException";
NSString	* const GPGErrorCodeKey = @"GPGErrorCodeKey";
NSString	* const GPGErrnoKey = @"GPGErrnoKey";


@implementation NSException(GPGExceptions)

+ (NSException *) exceptionWithGPGError:(GPGError)error userInfo:(NSDictionary *)additionalUserInfo
/*"
 * Returns a new NSException instance with name #GPGException,
 * reason defined as #GPGErrorDescription(error),
 * and userInfo dictionary filled with #GPGErrorCodeKey = error, 
 * #GPGErrnoKey = %errno (if error == #GPGErrorFileError), and additional userInfo.
 *
 * Used internally by the GPGME framework.
"*/
{
    NSParameterAssert(error != GPGME_No_Error);
    
    if(additionalUserInfo != nil){
        additionalUserInfo = [NSMutableDictionary dictionaryWithDictionary:additionalUserInfo];
        [(NSMutableDictionary *)additionalUserInfo setObject:[NSNumber numberWithInt:error] forKey:GPGErrorCodeKey];
    }
    else
        additionalUserInfo = [NSMutableDictionary dictionaryWithObject:[NSNumber numberWithInt:error] forKey:GPGErrorCodeKey];

    if(error == GPGME_File_Error)
        [(NSMutableDictionary *)additionalUserInfo setObject:[NSNumber numberWithInt:errno] forKey:GPGErrnoKey];
        
    return [NSException exceptionWithName:GPGException reason:GPGErrorDescription(error) userInfo:additionalUserInfo];
}

@end
