//
//  gpg.m
//  GPGME
//
//  Created by redbird on Thu Aug 02 2001.
//
//
//  Copyright (C) 2001 Mac GPG Project.
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
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx> or
//  developer e-mail addresses.
//

#import "gpg.h"
#import "gpgme.h"

@implementation GPG
- init
{
    context = [[GPGContext alloc] init];
    return self;
}

- initWithUsername:(NSString *)username
{
    [self init];
    [self setUsername:(NSString *)username];
    return self;
}

- initWithUsername:(NSString *)username passphraseCBTarget:(id)target selector:call_back userData:(id)arg
{
    [self init];
    [self setUsername:(NSString *)username];
    return self;
}

- (void)dealloc
{
    [context release];
    [user_key release];
    [passphrase_callback_target release];
    [passphrase_callback_arg release];
    [super dealloc];
}

- (void)setUsername:(NSString *)username
{
    int err = gpgme_op_keylist_start([context context], [username cString], 1);
    //help, now what?
}

//when a passphrase is needed [target call_back:arg] will be called (arg can be nil).
//you should not store the password in your program, you *must* ask the user for it
//each time.  call_back must return an NSString.

//xxx remember to make sure this is safe in final version - redbird
- (void)setPassphraseCBTarget:(id)target selector:(SEL)call_back userData:(id)arg
{
    passphrase_callback_target = [target retain];
    passphrase_callback_method = call_back;
    passphrase_callback_arg = [arg retain];
}

@end
