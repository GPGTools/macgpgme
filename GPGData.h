//
//  GPGData.h
//  GPGME
//
//  Created by stephane@sente.ch on Tue Aug 14 2001.
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
//  <stephane@sente.ch>.
//

#import <GPGME/GPGObject.h>


@class NSData;
@class NSMutableData;
@class NSString;


typedef enum {
    GPGDataTypeNone       = 0,
    GPGDataTypeData       = 1,
    GPGDataTypeFileHandle = 2, // Non-writable
    GPGDataTypeFile       = 3, // Non-writable
    GPGDataTypeDataSource = 4  // Non-writable
} GPGDataType;


@interface GPGData : GPGObject
{
    id				_dataSource;
    NSMutableData	*_retainedData;
}

// All initializers can raise a GPGException; in this case, a release is sent to self
- (id) init;
// Data is created without content
// type is set to GPGDataTypeNone; it can later be set to GPGDataTypeData
- (id) initWithData:(NSData *)someData;
// Copies NSData bytes
// type is set to GPGDataTypeData
- (id) initWithDataNoCopy:(NSMutableData *)someData;
// Doesn't copy data, but user needs to make sure that
// someData remains valid until dealloc
// type is set to GPGDataTypeData
- (id) initWithDataSource:(id)dataSource;
// dataSource must respond to selector data:readLength:
// dataSource is not retained
// data can only be read
- (id) initWithContentsOfFile:(NSString *)filename;
// Immediately opens file and copies content into memory; then it closes file
//- (id) initWithContentsOfFileNoCopy:(NSString *)filename;
- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length;
// Immediately opens file and copies partial content into memory; then it closes file

- (NSData *) data;
// Returns a copy of data
// WARNING: after having call this method, instance can't respond
// to any other message; it will raise an NSGenericException!!!
// Returns nil if it couldn't allocate enough memory

- (GPGDataType) type;

- (void) rewind;
// Prepares data in a way that the next call to -readDataOfLength: does start at the beginning of the data
// Can raise a GPGException

- (NSData *) readDataOfLength:(unsigned int)length;
// Reading starts from the current position
// Returned data length has the appropriate length, smaller or equal to length
// Returns nil when there isn't anything to read
// Read data should be copied, not referenced.
// Can raise a GPGException (but never a GPGErrorEOF one)
- (void) writeData:(NSData *)data;
// Writing starts from the current position
// Writes all data (makes a copy of it)
// Can raise a GPGException

@end

@interface NSObject(GPGDataSource)
- (NSData *) data:(GPGData *)data readLength:(unsigned int)maxLength;
// Returned data length must have a length smaller or equal to maxLength
// If there is nothing more to read, return nil
// Read data will be copied
@end
