//
//  GPGExceptions.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
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

#import <Foundation/NSException.h>
#import <GPGME/GPGDefines.h>
#import <GPGME/GPGEngine.h>


@class NSString;


/*"
 * A #GPGException can be raised by nearly any GPGME call...
 *
 * Reason: description of #GPGError.
 *
 * UserInfo:
 * _{GPGErrorCodeKey A #NSNumber containing a #GPGError value}
 * _{GPGErrnoKey A #NSNumber containing %errno; present only if #GPGError = #GPGErrorFileError}
"*/
GPG_EXPORT NSString	* const GPGException;
GPG_EXPORT NSString	* const GPGErrorCodeKey;
GPG_EXPORT NSString	* const GPGErrnoKey;


@interface NSException(GPGExceptions)
+ (NSException *) exceptionWithGPGError:(GPGError)error userInfo:(NSDictionary *)userInfo;
@end
