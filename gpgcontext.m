//
//  gpgcontext.m
//  gpglink
//
//  Created by johann on Thu Jun 21 2001.
//
//  Simple linkage to the gpgme objects.
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

#import "gpgcontext.h"

@implementation GPGContext
- init
{
    int      err;
    /* Create a new context. */
    err = gpgme_new (&context);
    /* Signal an error? */
    if (err) {
        /* Free the receiver. */
        return nil;
    } else {
        return self;
    }
}

- initWithGpgmeCtx:(GpgmeCtx)ctx
{
    context = ctx;
    return self;
}

- (void)dealloc
{
    gpgme_release (context);
    [super dealloc];
}

/* Get the underlying context object. */
- (GpgmeCtx) context
{
    return context;
}

- (void)cancel
{
    gpgme_cancel (context);
}

- (GpgmeCtx)wait:(int)hang
{
    return gpgme_wait(context, hang);
}

- (char *)notation
{
    return gpgme_get_notation(context);
}

- (void)setArmor:(int)armor
{
    gpgme_set_armor(context, armor);
}

- (void)setTextMode:(int)mode
{
    gpgme_set_textmode (context, mode);
}

- (void)setKeyListMode:(int)mode
{
    gpgme_set_keylist_mode (context, mode);
}

- (void)setPassphraseCB:(GpgmePassphraseCb)cb value:(void *)value
{
    gpgme_set_passphrase_cb (context, cb, value);
}

- (void)setProgressCB:(GpgmeProgressCb)cb value:(void *)value
{
    gpgme_set_progress_cb (context, cb, value);
}

- (void)clearSigners
{
    gpgme_signers_clear (context);
}

- (int)addSigner:(GpgmeKey)key
{
    return gpgme_signers_add (context, key);
}

- (GpgmeKey)enumSigner:(int)seq
{
    return gpgme_signers_enum (context, seq);
}

// Operations
- (int)signData:(GPGData *)in_data outData:(GPGData *)out_data mode:(int)mode
{
    // Should probably verify types, etc....
    return gpgme_op_sign (context, [in_data data], [out_data data], mode);
}
/* skip on the rest for now. */
@end
