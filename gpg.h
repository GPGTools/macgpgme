//
//  gpg.h
//  GPGME
//
//  Provides super easy to use interface to GPGContext.  Good for those who
//  just want GnuPG access to do basic things.
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

#import <Foundation/Foundation.h>
#import "gpgme.h"

@protocol GPGPassphraseCB

    - (NSString *)passphraseCB;

@end

@interface GPG : NSObject {
    GpgmeKey user_key;
    GpgmeCtx context;
    //id passphrase_callback_target;
}
- (id)init;
- (id)initWithUsername:(NSString *)username;
- (id)initWithUsername:(NSString *)username passphraseCBTarget:(id)target;
- (void)dealloc;

// user management
- (int)setUsername:(NSString *)username;
- (void)setPassphraseCBTarget:(id)target;
//- (id)passphraseCBTarget;
- (NSString *)getUserKeyAsXML;

// commands on data
- (NSString *)clearSign:(NSString *)data;
//- (NSString *)encrypt:(NSString *)data withRecipients:(NSArray *)recps;
//- (NSString *)encryptAndSign:(NSString *)data withRecipients(NSArray *)recps;
//- (NSString *)decrypt:(NSString *)data;
//- (int)verify:(NSString *)data;
//- (int)verify:(NSString *)data withSig:(NSString *)sig;

// key management
// these are delayed until we have a GPGKey class (GpgmeKey wrapper)
//- (NSArray *)listKeys:(NSString *)pattern;
//- (NSArray *)listSecretKeys:(NSString *)pattern;

// kluge methods; here until wrapper classes are done
- (NSString *)readGpgmeData:(GpgmeData)data;
@end
