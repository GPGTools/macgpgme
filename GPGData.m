//
//  GPGData.m
//  GPGME
//
//  Created by davelopper@users.sourceforge.net on Tue Aug 14 2001.
//
//
//  Copyright (C) 2001-2002 Mac GPG Project.
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

#import "GPGData.h"
#import "GPGExceptions.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _data		((GpgmeData)_internalRepresentation)
#define _dataPtr	((GpgmeData *)&_internalRepresentation)


@implementation GPGData
/*"
 * A lot of data has to be exchanged between the user and the crypto engine,
 * like plaintext messages, ciphertext, signatures and information about the keys.
 * The technical details about exchanging the data information are completely
 * abstracted by GPGME. The user provides and receives the data via #GPGData instances,
 * regardless of the communication protocol between GPGME and the crypto engine in use.
"*/

- (id) init
/*"
 * Data is created without content. Type is set to #GPGDataTypeNone; it can later
 * be set to #GPGDataTypeData.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError = gpgme_data_new(_dataPtr);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];
    
    return self;
}

- (id) initWithData:(NSData *)someData
/*"
 * Copies someData's bytes.
 * Type is set to #GPGDataTypeData.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError = gpgme_data_new_from_mem(_dataPtr, [someData bytes], [someData length], 1);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];

    return self;
}

- (id) initWithDataNoCopy:(NSMutableData *)someData
/*"
 * Doesn't copy someData, but user needs to make sure that someData remains valid
 * until #dealloc. Type is set to #GPGDataTypeData.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
#warning Is someData really to be modified??? Ask Werner.
    // No, it seems that data is not modified, because
    // there is a const char *buffer => buffer is not modified
    // => No difference with -initWithData: ???
    // Difference is that with this initialization, we know that
    // Gpgme_data will not be modified.
    // The same applies for gpgme_data_new_from_file()
    ////////// NOT SURE ABOUT THIS... ////////////////
    GpgmeError	anError = gpgme_data_new_from_mem(_dataPtr, [someData mutableBytes], [someData length], 0);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];
    [_retainedData retain];
    
    return self;
}

static int readCallback(void *object, char *destinationBuffer, size_t destinationBufferSize, size_t *readLengthPtr)
{
    // Returns GPGME_No_Error if it could read anything, else any other value.
    // In case of rewinding (destinationBuffer = NULL), returns GPGME_No_Error if implemented, else any other value.
    volatile NSData	*readData;
    
    NSCParameterAssert(destinationBufferSize != 0 || (destinationBuffer == NULL && readLengthPtr == NULL));

    NS_DURING
        readData = [((GPGData *)object)->_dataSource data:((GPGData *)object) readLength:destinationBufferSize];
    NS_HANDLER
        if([[localException name] isEqualToString:GPGException]){
            NSNumber	*errorCodeNumber = [[localException userInfo] objectForKey:GPGErrorCodeKey];

            NSCAssert1(errorCodeNumber != nil && [errorCodeNumber intValue] == GPGErrorNotImplemented, @"### GPGException raised by GPGData dataSource is not GPGErrorNotImplemented (%@)", errorCodeNumber);
            
            // Rewinding not implemented
            
            return !GPGME_No_Error;
        }
        else
            [localException raise];
    NS_ENDHANDLER

    if(readData == nil){
        // Rewinding or EOF
        if(readLengthPtr != NULL)
            *readLengthPtr = 0;
        
        return (destinationBuffer == NULL ? GPGME_No_Error:!GPGME_No_Error);
    }
    else{
        size_t	aLength = [(NSData *)readData length];
        
        if(readLengthPtr != NULL)
            *readLengthPtr = aLength;
        NSCAssert(aLength <= destinationBufferSize, @"### GPGData dataSource may not return more bytes than given capacity!");
        [(NSData *)readData getBytes:destinationBuffer];
        
        return GPGME_No_Error;
    }
}

- (id) initWithDataSource:(id)dataSource
/*"
 * dataSource must respond to selector #{data:readLength:}. dataSource is not
 * retained. dataSource is invoked to retrieve data on-demand, and it can
 * supply the data in any way it wants; this is the most flexible data type
 * GPGME provides. However it cannot be used to write data.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError;

    NSParameterAssert(dataSource != nil && [dataSource respondsToSelector:@selector(data:readLength:)]);

    anError = gpgme_data_new_with_read_cb(_dataPtr, readCallback, self);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];
    _dataSource = dataSource; // We don't retain dataSource
    
    return self;
}

- (id) initWithContentsOfFile:(NSString *)filename
/*"
 * Immediately opens file and copies content into memory; then it closes file.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    GpgmeError	anError = gpgme_data_new_from_file(_dataPtr, [filename fileSystemRepresentation], 1);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];
    
    return self;
}

- (id) initWithContentsOfFileNoCopy:(NSString *)filename
// Not yet supported as of 0.3.0
// Can raise a GPGException; in this case, a release is sent to self
{
    GpgmeError	anError = gpgme_data_new_from_file(_dataPtr, [filename fileSystemRepresentation], 0);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];
    
    return self;
}

- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length
/*"
 * Immediately opens file and copies partial content into memory; then it closes
 * file.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    // We don't provide a method to match the case where filename is NULL
    // and filePtr (FILE *) is not NULL (both arguments are exclusive),
    // because we generally don't manipulate FILE * types in Cocoa.
    GpgmeError	anError = gpgme_data_new_from_filepart(_dataPtr, [filename fileSystemRepresentation], NULL, offset, length);

    if(anError != GPGME_No_Error){
        _data = NULL;
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:_data];

    return self;
}

- (void) dealloc
{
    GpgmeData	cachedData = _data;

    if(_retainedData != nil)
        [_retainedData release];
    [super dealloc];

    // We could have a problem here if we set ourself as callback
    // and _data is deallocated later than us!!!
    // This shouldn't happen, but who knows...
    if(cachedData != NULL)
        gpgme_data_release(cachedData);
}

- (unsigned long long) availableDataLength
/*"
 * Returns the amount of bytes available without changing the read pointer.
 * This is not supported by all types of data objects.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * If end of data object is reached or no data is currently available,
 * it returns 0. To know if there are more bytes to read, you must
 * invoke #{-isAtEnd}.
"*/
{
    size_t		availableDataLength;
    GpgmeError	anError = gpgme_data_read(_data, NULL, 0, &availableDataLength);

    if(anError != GPGME_No_Error && anError != GPGErrorEOF)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return availableDataLength;
}

- (unsigned long long) length
/*"
 * Convenience method. Returns length of all data.
 * It rewinds receiver, then reads available data length
 * and returns it. Read pointer is reset.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * Can raise a #GPGException.
"*/
{
    [self rewind];
    
    return [self availableDataLength];
}

- (BOOL) isAtEnd
/*"
 * Returns YES if there are no more bytes to read (EOF). If #{-availableDataLength} returns 0,
 * it means that either there is nothing more to read, or there is currently nothing to read.
 * Read pointer is not moved.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * Can raise a #GPGException.
"*/
{
    size_t		availableDataLength;
    GpgmeError	anError = gpgme_data_read(_data, NULL, 0, &availableDataLength);

    if(anError != GPGME_No_Error)
        if(anError != GPGErrorEOF)
            [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
        else
            return YES;

    return NO;
}

- (NSData *) availableData
/*"
 * Returns a copy of data, read from current position, up to end of data.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError		anError;
    size_t			bufferSize = NSPageSize();
    NSZone			*aZone = NSDefaultMallocZone();
    char			*bufferPtr = (char *)NSZoneMalloc(aZone, bufferSize);
    NSMutableData	*readData = [NSMutableData dataWithCapacity:bufferSize];
    
    do{
        size_t	aReadLength;
        
        anError = gpgme_data_read(_data, bufferPtr, bufferSize, &aReadLength);
        // CAUTION: function can return a length of 0, without being at EOF
        // => could potentially turn into a dead-lock here!
        if(anError == GPGME_No_Error && aReadLength > 0)
            [readData appendBytes:bufferPtr length:aReadLength];
    }while(anError == GPGME_No_Error);

    NSZoneFree(aZone, bufferPtr);
    if(anError != GPGME_EOF)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];

    return readData;
}

- (NSData *) data
/*"
 * Convenience method. Returns a copy of all data.
 * It rewinds receiver, then reads data
 * until EOF, and returns it.
 *
 * Can raise a #GPGException.
"*/
{
    [self rewind];
    
    return [self availableData];
}

- (GPGDataType) type
/*"
 * Returns the type of the data object.
"*/
{
    GPGDataType	type = gpgme_data_get_type(_data);
    
    NSAssert(type != GPGME_DATA_TYPE_NONE, @"### _data is not a valid pointer");
    
    return type;
}

- (void) rewind
/*"
 * Prepares data in a way that the next call to #{-readDataOfLength:} starts at
 * the beginning of the data. This has to be done for all types of #GPGData instances.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_data_rewind(_data);
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSData *) readDataOfLength:(unsigned int)length
/*"
 * Reading starts from the current position. Returned data has the
 * appropriate size, smaller or equal to length. Returns nil when there isn't
 * anything more to read (EOF). Read data should be copied, not referenced.
 *
 * Can raise a #GPGException (but never a #GPGErrorEOF one).
"*/
{
    GpgmeError		anError;
    NSMutableData	*readData = [NSMutableData dataWithLength:length];
    size_t			aReadLength;
    
    anError = gpgme_data_read(_data, [readData mutableBytes], length, &aReadLength);
    if(anError == GPGME_EOF)
        return nil;
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    [readData setLength:aReadLength];

    return readData;
}

- (void) writeData:(NSData *)data
/*"
 * Writing starts from the current position. Writes all data (makes a copy of it).
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError = gpgme_data_write(_data, [data bytes], [data length]);
    
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

@end


@implementation GPGData(GPGInternals)

- (GpgmeData) gpgmeData
{
    return _data;
}

@end


// We need to write this fake implementation (not compiled!)
// just to force autodoc to take our comments in account!
#ifdef FAKE_IMPLEMENTATION_FOR_AUTODOC
@implementation NSObject(GPGDataSource)
- (NSData *) data:(GPGData *)data readLength:(unsigned int)maxLength
/*"
 * Returned data must have a length smaller or equal to maxLength.
 * If there is no data currently available, return an empty data.
 * If there is nothing more to read (EOF), return nil.
 * If maxLength is 0, dataSource is asked to reset/rewind its internal pointer;
 * if it is not possible, raise a #GPGException with error #GPGErrorNotImplemented,
 * else return nil.
 *
 * Returned data will be copied.
"*/
{}
@end
#endif
