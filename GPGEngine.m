//
//  GPGEngine.m
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

#import "GPGEngine.h"
#import "GPGObject.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


NSString *GPGCheckVersion(NSString *requiredVersion)
{
    const char	*aCString;
    NSString	*aString = nil;

    [GPGObject initialize];
    aCString = gpgme_check_version(requiredVersion == nil ? NULL:[requiredVersion UTF8String]);

    if(aCString != NULL)
        aString = [NSString stringWithUTF8String:aCString];
    
    return aString;
}

GPGError GPGCheckEngine()
{
    [GPGObject initialize];

    return gpgme_check_engine();
}

GPGError GPGEngineCheckVersion(GPGProtocol protocol)
{
    [GPGObject initialize];

    return gpgme_engine_check_version(protocol);
}

NSString *GPGEngineInfoAsXMLString()
{
    const char	*aCString;
    NSString	*aString = nil;

    [GPGObject initialize];
    aCString = gpgme_get_engine_info();
    if(aCString != NULL)
        aString = [NSString stringWithUTF8String:aCString];
    
    return aString;
}

NSString *GPGErrorDescription(GPGError error)
{
    const char	*aCString = gpgme_strerror(error);
    NSString	*aString = nil;

    if(aCString != NULL)
        aString = [NSString stringWithUTF8String:aCString];

    return aString;
}
