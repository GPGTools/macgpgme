//
//  GPGData.h
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
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
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx>
//

#import <GPGME/GPGObject.h>


@class NSData;
@class NSMutableData;
@class NSString;


typedef enum {
    GPGDataTypeNone       = 0,
    GPGDataTypeData       = 1,
    GPGDataTypeFileHandle = 2, /*"Non-writable"*/
    GPGDataTypeFile       = 3, /*"Non-writable"*/
    GPGDataTypeDataSource = 4  /*"Non-writable"*/
} GPGDataType;


@interface GPGData : GPGObject
{
    id				_dataSource;
    NSMutableData	*_retainedData;
}

/*"Initializers"*/
- (id) init;
- (id) initWithData:(NSData *)someData;
- (id) initWithDataNoCopy:(NSMutableData *)someData;
- (id) initWithDataSource:(id)dataSource;
- (id) initWithContentsOfFile:(NSString *)filename;
//- (id) initWithContentsOfFileNoCopy:(NSString *)filename;
- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length;

/*"Attributes"*/
- (NSData *) data;

- (GPGDataType) type;

/*"Operations"*/
- (void) rewind;

- (NSData *) readDataOfLength:(unsigned int)length;
- (void) writeData:(NSData *)data;

@end

@interface NSObject(GPGDataSource)
- (NSData *) data:(GPGData *)data readLength:(unsigned int)maxLength;
@end
