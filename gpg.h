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
#import "gpgcontext.h"

@interface GPG : NSObject {
    NSString *user_key;
    GPGContext *context;
}
- init;
- initWithUsername:(NSString *)username withPassphrase:(NSMutableString *)passphrase;
- (void)dealloc;
- (void)setUsername:(NSString *)username;
- (void)setPassphrase:(NSMutableString *)passphrase;
//- (NSString)clearSign:(NSString *)data;
//- (NSString)encrypt:(NSString *)data withRecipients:(NSArray *)recp;
//- (NSString)encryptAndSign:(NSString *)data withRecipients(NSArray *)recp;
//- (NSString)decrypt:(NSString *)data;
//- (int)verify:(NSString *)data withSig:(NSString *)sig;
//- (NSArray)listKeys:(NSString *)pattern;

@end
