//
//  GPGData.h
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

#ifndef GPGDATA_H
#define GPGDATA_H

#include <GPGME/GPGObject.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSData;
@class NSMutableData;
@class NSString;


/*"
 * The #GPGDataType type specifies the type of a #GPGData instances.
 * The following data types are available:
 * _{GPGDataTypeNone        This specifies that the type is not yet determined.}
 * _{GPGDataTypeData        This specifies that the data is stored in memory.}
 * _{GPGDataTypeFileHandle  This type is not implemented.}
 * _{GPGDataTypeFile        This type is not implemented.}
 * _{GPGDataTypeDataSource  This type specifies that the data is provided by a data source implemented by the user.}
"*/
typedef enum {
    GPGDataTypeNone       = 0,
    GPGDataTypeData       = 1,
    GPGDataTypeFileHandle = 2,
    GPGDataTypeFile       = 3,
    GPGDataTypeDataSource = 4
} GPGDataType;


/*"
 * The #GPGDataEncoding type specifies the encoding of a #GPGData object.
 * This encoding is useful to give the backend a hint on the type of data.
 * The following data types are available:
 * _{GPGDataEncodingNone    This specifies that the encoding is not known.
 *                          This is the default for a new data object.
 *                          The backend will try its best to detect the
 *                          encoding automatically.}
 * _{GPGDataEncodingBinary  This specifies that the data is encoding in binary form;
 *                          i.e. there is no special encoding.}
 * _{GPGDataEncodingBase64  This specifies that the data is encoded using the Base-64
 *                          encoding scheme as used by MIME and other protocols.}
 * _{GPGDataEncodingArmor   This specifies that the data is encoded in an armored
 *                          form as used by OpenPGP and PEM.}
"*/
typedef enum {
    GPGDataEncodingNone   = 0,
    GPGDataEncodingBinary = 1,
    GPGDataEncodingBase64 = 2,
    GPGDataEncodingArmor  = 3
} GPGDataEncoding;


@interface GPGData : GPGObject /*"NSObject"*/
{
    id				_dataSource;
    NSMutableData	*_retainedData;
}

/*"Creating data buffers"*/
- (id) init;
- (id) initWithData:(NSData *)someData;
- (id) initWithDataNoCopy:(NSMutableData *)someData;
- (id) initWithString:(NSString *)string;
- (id) initWithDataSource:(id)dataSource;
- (id) initWithContentsOfFile:(NSString *)filename;
//- (id) initWithContentsOfFileNoCopy:(NSString *)filename;
- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length;

/*"Attributes"*/
- (NSData *) data;
- (NSString *) string;
- (unsigned long long) length;
- (NSData *) availableData;
- (unsigned long long) availableDataLength;
- (BOOL) isAtEnd;

- (GPGDataType) type;

/*"Encoding"*/
- (GPGDataEncoding) encoding;
- (void) setEncoding:(GPGDataEncoding)encoding;

/*"Manipulating data buffers"*/
- (void) rewind;

- (NSData *) readDataOfLength:(unsigned int)length;
- (void) writeData:(NSData *)data;

@end


@interface NSObject(GPGDataSource)
- (NSData *) data:(GPGData *)data readLength:(unsigned int)maxLength;
@end

#ifdef __cplusplus
}
#endif
#endif /* GPGDATA_H */
