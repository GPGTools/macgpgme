//
//  GPGData.h
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2005 Mac GPG Project.
//  
//  This code is free software; you can redistribute it and/or modify it under
//  the terms of the GNU Lesser General Public License as published by the Free
//  Software Foundation; either version 2.1 of the License, or (at your option)
//  any later version.
//  
//  This code is distributed in the hope that it will be useful, but WITHOUT ANY
//  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
//  FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
//  details.
//  
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program; if not, visit <http://www.gnu.org/> or write to the
//  Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, 
//  MA 02111-1307, USA.
//  
//  More info at <http://macgpg.sourceforge.net/>
//

#ifndef GPGDATA_H
#define GPGDATA_H

#include <MacGPGME/GPGObject.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


@class NSData;
@class NSFileHandle;
@class NSMutableData;
@class NSString;


/*"
 * The #GPGDataEncoding type specifies the encoding of a #GPGData object. This
 * encoding is useful to give the backend a hint on the type of data. The
 * following data types are available:
 * _{GPGDataEncodingNone    This specifies that the encoding is not known.
 *                          This is the default for a new data object. The
 *                          backend will try its best to detect the encoding
 *                          automatically.}
 * _{GPGDataEncodingBinary  This specifies that the data is encoding in binary
 *                          form; i.e. there is no special encoding.}
 * _{GPGDataEncodingBase64  This specifies that the data is encoded using the 
 *                          Base-64 encoding scheme as used by MIME and other
 *                          protocols.}
 * _{GPGDataEncodingArmor   This specifies that the data is encoded in an 
 *                          armored form as used by OpenPGP and PEM.}
"*/
typedef enum {
    GPGDataEncodingNone   = 0,
    GPGDataEncodingBinary = 1,
    GPGDataEncodingBase64 = 2,
    GPGDataEncodingArmor  = 3
} GPGDataEncoding;


/*"
 * The #GPGDataOffsetType type specifies how the offset should be interpreted
 * when repositioning read/write (#{-seekToFileOffset:offsetType:} and
 * #{-data:seekToFileOffset:offsetType:}). It must be one of the following
 * symbolic constants:
 * _{GPGDataStartPosition    Offset is a count of characters from the
 *                           beginning of the data object.}
 * _{GPGDataCurrentPosition  Offset is a count of characters from the current 
 *                           file position. This count may be positive or
 *                           negative.}
 * _{GPGDataEndPosition      Offset is a count of characters from the end of
 *                           the data object. A negative count specifies a
 *                           position within the current extent of the data
 *                           object; a positive count specifies a position 
 *                           past the current end. If you set the position 
 *                           past the current end, and actually write data, 
 *                           you will extend the data object with zeros up to 
 *                           that position.}
"*/
typedef enum {
    GPGDataStartPosition    = 0,
    GPGDataCurrentPosition  = 1,
    GPGDataEndPosition      = 2
} GPGDataOffsetType;


@interface GPGData : GPGObject /*"NSObject"*/
{
    id		_objectReference;
    void	*_callbacks;
}

/*"
 * Creating memory based data buffers
"*/
- (id) init;
- (id) initWithData:(NSData *)someData;
- (id) initWithDataNoCopy:(NSData *)someData;
- (id) initWithContentsOfFile:(NSString *)filename;
//- (id) initWithContentsOfFileNoCopy:(NSString *)filename;
- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length;

/*"
 * Creating file based data buffers
"*/
- (id) initWithFileHandle:(NSFileHandle *)fileHandle;

/*"
 * Creating callback based data buffers
"*/
- (id) initWithDataSource:(id)dataSource;

/*"
 * Encoding
"*/
- (GPGDataEncoding) encoding;
- (void) setEncoding:(GPGDataEncoding)encoding;

/*"
 * Manipulating data buffers
"*/
- (unsigned long long) seekToFileOffset:(unsigned long long)offset offsetType:(GPGDataOffsetType)offsetType;

- (NSData *) readDataOfLength:(unsigned long long)length;
- (unsigned long long) writeData:(NSData *)data;

/*"
 * Manipulating meta-data
"*/
- (NSString *) filename;
- (void) setFilename:(NSString *)filename;

@end


@interface GPGData(GPGExtensions)
/*"
 * Convenience initializer
"*/
- (id) initWithString:(NSString *)string;

/*"
 * Convenience methods
"*/
- (unsigned long long) length;
- (NSData *) data;
- (NSString *) string;
- (NSData *) availableData;
- (unsigned long long) availableDataLength;

- (BOOL) isAtEnd;

- (void) rewind;

@end


@interface NSObject(GPGDataSource)
- (NSData *) data:(GPGData *)data readDataOfLength:(unsigned int)maxLength;
- (unsigned long long) data:(GPGData *)data writeData:(NSData *)writeData;
- (unsigned long long) data:(GPGData *)data seekToFileOffset:(unsigned long long)fileOffset offsetType:(GPGDataOffsetType)offsetType;
- (void) dataRelease:(GPGData *)data;
@end

#ifdef __cplusplus
}
#endif
#endif /* GPGDATA_H */
