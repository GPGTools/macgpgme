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

const char *_gpgPassphraseCB(void *cb_value, const char *desc, void *r_hd);
id passphrase_callback_target;

@implementation GPG
- (id)init
{
    int err = gpgme_new (&context);
    if (err)	{
        return nil;
    }
    else	{
        return self;
    }
}

- (id)initWithUsername:(NSString *)username
{
    [self init];
    [self setUsername:username];
    return self;
}

- (id)initWithUsername:(NSString *)username passphraseCBTarget:(id)target
{
    [self init];
    [self setUsername:username];
    [self setPassphraseCBTarget:target];
    return self;
}

- (void)dealloc
{
    gpgme_release (context);
    gpgme_key_release (user_key);
    [passphrase_callback_target release];
    [super dealloc];
}

// user management

- (int)setUsername:(NSString *)username
{
    int err = gpgme_op_keylist_start(context, [username cString], 1);
    if (err) return err;
    
    err = gpgme_op_keylist_next(context, &user_key);
    if (err) return err;
    
    err = gpgme_signers_add(context, user_key);
    return err;
}

- (void)setPassphraseCBTarget:(id)target
{
    [passphrase_callback_target autorelease];
    passphrase_callback_target = [target retain];
    gpgme_set_passphrase_cb(context, _gpgPassphraseCB, self);
}

/*- (id)passphraseCBTarget
{
    return passphrase_callback_target;
}*/

- (NSString *)getUserKeyAsXML
{
    return [[NSString alloc] initWithCString:gpgme_key_get_as_xml(user_key)];
}

// commands on data

- (NSString *)clearSign:(NSString *)data
{
    GpgmeData indata, outdata;
    int err = gpgme_data_new (&indata);
    if (err) return @"an error occured indata";
    err = gpgme_data_new (&outdata);
    if (err) return @"an error occured outdata";
    err = gpgme_data_write(indata, [data cString], [data cStringLength]);
    if (err) return @"an error occured data_write";
    context = gpgme_wait(context, 5);
    err = gpgme_op_sign_start (context, indata, outdata, 2);
    if (err) return [[NSString alloc] initWithFormat:@"error %d occured", err];
    gpgme_data_release (indata);
    gpgme_data_release (outdata);
    if (err) return @"an error occured";
    return [self readGpgmeData:outdata];
}

//kluge methods

- (NSString *)readGpgmeData:(GpgmeData)data
{
    char       buf[1024];
    size_t     n_read;
    NSString *str, *str_temp;
    int err;
    
    err = gpgme_data_rewind (data);
    
    // Does all of this work correctly (since presumably now all the string objects)
    // are flagged autorelease, or don't I understand this yet?
    str = [[NSString alloc] init];
    [str autorelease];
    while ( !(err = gpgme_data_read (data, buf, 1024, &n_read)) ) {
        str_temp = [NSString stringWithCString: buf length: n_read];
        str      = [str stringByAppendingString: str_temp];
    }
    return str;
}

// private methods

// This being the function that GPGME will actually call to get the passphrase
//  cb_value <-- user data, hopefully a pointer to the GPG object
const char *_gpgPassphraseCB(void *cb_value, const char *desc, void *r_hd)
{
    //GPG *gpgObj = (GPG*)cb_value;
    
    // Fetch the target object and call it's CB...
    // TODO: Find out about and support the other arguments
    //NSString *passphrase = [ [ gpgObj passphraseCBTarget ] passphraseCB ];
    
    //  Also, we need to make sure that our passphrase is deallocated later
    //  May also want to support the keyring internally here.
    //return [ passphrase cString ];
    return [[[NSString alloc] initWithString:passphrase_callback_target] cString];
}

@end
