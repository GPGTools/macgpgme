//
//  gpgdata.m
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

#import "gpgdata.h"
#include <stdio.h>

@implementation GPGData
- init
{
    int      err;
    /* Create a new data object. */
    err = gpgme_data_new (&data);
    /* Signal an error? */
    if (err) {
        /* Free the receiver. */
        return nil;
    } else {
        return self;
    }
}

- initWithGpgmeData:(GpgmeData)data_in
{
    data = data_in;
    return self;
}

- initWithString:(NSString *)str
{
    return [self initWithMem: [str cString] size: [str cStringLength]
                 copy: 1];
}

- initWithMem:(char *)buffer size:(int)size copy:(int)copy
{
    int err;
    err = gpgme_data_new_from_mem (&data, buffer, size, copy);
    if (err) {
        return nil;
    } else {
        return self;
    }
}

- (void)dealloc
{
    gpgme_data_release (data);
    [super dealloc];
}

- (GpgmeData)data
{
    return data;
}

- (void)print
{
    // sample print method
    char buf[100];
    size_t nread;
    GpgmeError err;

    err = gpgme_data_rewind ( data );
    // fail_if_err (err);
    while ( !(err = gpgme_data_read ( data, buf, 100, &nread )) ) {
        fwrite ( buf, nread, 1, stdout );
    }
    // if (err != GPGME_EOF) 
    //     fail_if_err (err);
}

- (NSString *)toString
{
    // Get the data as a string.
    char       buf[1024];
    size_t     n_read;
    GpgmeError err;
    NSString   *str, *str_temp;

    err = gpgme_data_rewind (data);
    // fail_if_err (err);
    
    // Does all of this work correctly (since presumably now all the string objects)
    // are flagged autorelease, or don't I understand this yet?
    str = [[NSString alloc] init];
    [str autorelease];
    while ( !(err = gpgme_data_read (data, buf, 1024, &n_read)) ) {
        // Does this copy the old string?  Presumably, since stringWithCStringNoCopy exists.
        str_temp = [NSString stringWithCString: buf length: n_read];
        str      = [str stringByAppendingString: str_temp];
    }
    // if (err != GPGME_EOF) 
    //     fail_if_err (err);
    
    return str;
}
@end
