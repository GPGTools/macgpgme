//
//  gpgcontext.h
//  gpglink
//
//  Created by johann on Thu Jun 21 2001.
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
#import "gpgdata.h"
#include "gpgme.h"

@interface GPGContext : NSObject {
    GpgmeCtx context;
}
- init;
- initWithGpgmeCtx:(GpgmeCtx)ctx;
- (void)dealloc;
- (GpgmeCtx)context;
- (void)cancel;
- (GpgmeCtx)wait:(int)hang;
- (char *)notation;
- (void)setArmor:(int)armor;
- (void)setTextMode:(int)mode;
- (void)setKeyListMode:(int)mode;
- (void)setPassphraseCB:(GpgmePassphraseCb)cb value:(void *)value;
// - (void)setPassphrase:(NSString *)phrase;
- (void)setProgressCB:(GpgmeProgressCb)cb value:(void *)value;
- (void)clearSigners;
- (int)addSigner:(GpgmeKey)key;
- (GpgmeKey)enumSigner:(int)seq;
/* - sigStatus; */
/* - sigKey; */

// convenience functions for normal use
// - (int)encrypt:recp in:in out:out;
// - (int)decrypt:in out:out;
- (int)signData:(GPGData *)in_data outData:(GPGData *)out_data mode:(int)mode;
// - (int)verify:sig text:text r_status:(int*)r_status;
// - (int)import:keydata;
// - (int)export:recp keydata:keydata;
// - (int)genkey:(char *)params pubkey:pubkey seckey:seckey;
// - (int)delete:key allow_secret:(int)allow_secret;
@end
