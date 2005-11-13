//
//  GPGData.m
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

#include <MacGPGME/GPGData.h>
#include <MacGPGME/GPGExceptions.h>
#include <MacGPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


#define _data		((gpgme_data_t)_internalRepresentation)


@implementation GPGData
/*"
 * A lot of data has to be exchanged between the user and the crypto engine,
 * like plaintext messages, ciphertext, signatures and information about the
 * keys. The technical details about exchanging the data information are
 * completely abstracted by GPGME. The user provides and receives the data via
 * #GPGData instances, regardless of the communication protocol between GPGME
 * and the crypto engine in use. GPGData contains both data and meta-data, e.g.
 * file name.
 *
 * Data objects can be based on memory, files, or callback methods provided by
 * the user (data source). Not all operations are supported by all objects.
 *
 * #{Memory Based Data Buffers}
 *
 * Memory based data objects store all data in allocated memory.  This is
 * convenient, but only practical for an amount of data that is a fraction of
 * the available physical memory. The data has to be copied from its source
 * and to its destination, which can often be avoided by using one of the
 * other data object.
 * Here are the methods to initialize memory based data buffers:
 * _{-init }
 * _{-initWithData:}
 * _{-initWithDataNoCopy:}
 * _{-initWithContentsOfFile:}
 * _{-initWithContentsOfFile:atOffset:length:}
 *
 * #{File Based Data Buffers}
 *
 * File based data objects operate directly on file descriptors or streams.
 * Only a small amount of data is stored in core at any time, so the size of
 * the data objects is not limited by GPGME.
 * Here are the methods to initialize file based data buffers:
 * _{-initWithFileHandle:}
 *
 * #{Callback Based Data Buffers}
 *
 * If neither memory nor file based data objects are a good fit for your
 * application, you can provide a data source implementing
 * #{NSObject(GPGDataSource)} methods and create a data object with this data
 * source.
 * Here are the methods to initialize callback based data buffers:
 * _{-initWithDataSource: }
"*/

- (id) init
/*"
 * Data is created without content and is memory based.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new(&aData);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    
    return self;
}

- (id) initWithData:(NSData *)someData
/*"
 * Copies someData's bytes.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_mem(&aData, [someData bytes], [someData length], 1);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];

    return self;
}

- (id) initWithDataNoCopy:(NSData *)someData
/*"
 * Doesn't copy someData, but retains it.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_mem(&aData, ([someData respondsToSelector:@selector(mutableBytes)] ? [(NSMutableData *)someData mutableBytes]:[someData bytes]), [someData length], 0);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    ((GPGData *)self)->_objectReference = [someData retain];
    
    return self;
}

static ssize_t readCallback(void *object, void *destinationBuffer, size_t destinationBufferSize)
{
    // Returns the number of bytes read, or -1 on error. Sets errno in case of error.
    NSData	*readData = nil;
    ssize_t	readLength = 0;
    
    NSCParameterAssert(destinationBufferSize != 0 && destinationBuffer != NULL);

    NS_DURING
        readData = [((GPGData *)object)->_objectReference data:((GPGData *)object) readDataOfLength:destinationBufferSize];
    NS_HANDLER
        if([[localException name] isEqualToString:GPGException]){
            NSNumber	*errorNumber = [[localException userInfo] objectForKey:GPGErrorKey];
            int			errorCodeAsErrno;
            
            NSCAssert(errorNumber != nil, @"### GPGException raised by GPGData dataSource has no error");
            errorCodeAsErrno = gpg_err_code_to_errno(gpgme_err_code([errorNumber intValue]));
            NSCAssert2(errorCodeAsErrno != 0, @"### GPGException raised by GPGData dataSource has not a system error errorCode (%@: %@)", errorNumber, GPGErrorDescription([errorNumber intValue]));

            errno = errorCodeAsErrno;
            
            return -1;
        }
        else
            [localException raise];
    NS_ENDHANDLER

    if(readData != nil){
        readLength = [readData length];

        if(readLength > 0){
            NSCAssert(((size_t)readLength) <= destinationBufferSize, @"### GPGData dataSource may not return more bytes than given capacity!");
            [readData getBytes:destinationBuffer];
        }
    }
    
    return readLength;
}

static ssize_t writeCallback(void *object, const void *buffer, size_t size)
{
    // Returns the number of bytes written, or -1 on error. Sets errno in case of error.
    unsigned long long	writeLength = 0;
    NSData				*data = [NSData dataWithBytesNoCopy:(void *)buffer length:size freeWhenDone:NO];

    NS_DURING
        writeLength = [((GPGData *)object)->_objectReference data:((GPGData *)object) writeData:data];
    NS_HANDLER
        if([[localException name] isEqualToString:GPGException]){
            NSNumber	*errorNumber = [[localException userInfo] objectForKey:GPGErrorKey];
            int			errorCodeAsErrno;

            NSCAssert(errorNumber != nil, @"### GPGException raised by GPGData dataSource has no error");
            errorCodeAsErrno = gpg_err_code_to_errno(gpgme_err_code([errorNumber intValue]));
            NSCAssert2(errorCodeAsErrno != 0, @"### GPGException raised by GPGData dataSource has not a system error errorCode (%@: %@)", errorNumber, GPGErrorDescription([errorNumber intValue]));

            errno = errorCodeAsErrno;

            return -1;
        }
        else
            [localException raise];
    NS_ENDHANDLER

    return writeLength;
}

static off_t seekCallback(void *object, off_t offset, int whence)
{
    // Returns the number of bytes written, or -1 on error. Sets errno in case of error.
    off_t	newPosition = 0;

    NS_DURING
        newPosition = [((GPGData *)object)->_objectReference data:((GPGData *)object) seekToFileOffset:offset offsetType:whence];
    NS_HANDLER
        if([[localException name] isEqualToString:GPGException]){
            NSNumber	*errorNumber = [[localException userInfo] objectForKey:GPGErrorKey];
            int			errorCodeAsErrno;

            NSCAssert(errorNumber != nil, @"### GPGException raised by GPGData dataSource has no error");
            errorCodeAsErrno = gpg_err_code_to_errno(gpgme_err_code([errorNumber intValue]));
            NSCAssert2(errorCodeAsErrno != 0, @"### GPGException raised by GPGData dataSource has not a system error errorCode (%@: %@)", errorNumber, GPGErrorDescription([errorNumber intValue]));

            errno = errorCodeAsErrno;

            return -1;
        }
        else
            [localException raise];
    NS_ENDHANDLER

    return newPosition;
}

static void releaseCallback(void *object)
{
    [((GPGData *)object)->_objectReference dataRelease:((GPGData *)object)];
}

- (id) initWithDataSource:(id)dataSource
/*"
 * dataSource must implement some of the methods declared in
 * #{NSObject(GPGDataSource)} informal protocol. dataSource is not retained.
 * dataSource is invoked to read/write data on-demand, and it can
 * supply the data in any way it wants; this is the most flexible data type
 * GPGME provides.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t		aData;
    gpgme_error_t		anError;
    gpgme_data_cbs_t	callbacks;

    NSParameterAssert(dataSource != nil);

    callbacks = (gpgme_data_cbs_t)NSZoneMalloc([self zone], sizeof(struct gpgme_data_cbs));
    if([dataSource respondsToSelector:@selector(data:readDataOfLength:)])
        callbacks->read = readCallback;
    if([dataSource respondsToSelector:@selector(data:writeData:)])
        callbacks->write = writeCallback;
    if([dataSource respondsToSelector:@selector(data:seekToFileOffset:offsetType:)])
        callbacks->seek = seekCallback;
    if([dataSource respondsToSelector:@selector(data:dataRelease:)])
        callbacks->release = releaseCallback;
    
    NSParameterAssert(callbacks->read != NULL || callbacks->write != NULL);

    anError = gpgme_data_new_from_cbs(&aData, callbacks, self);

    if(anError != GPG_ERR_NO_ERROR){
        NSZoneFree([self zone], callbacks);
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    NSAssert(self == [self initWithInternalRepresentation:aData], @"Tried to change self! Impossible due to callback registration.");
    _objectReference = dataSource; // We don't retain dataSource
    _callbacks = callbacks;
    
    return self;
}

- (id) initWithContentsOfFile:(NSString *)filename
/*"
 * Immediately opens file named filename (which must be an absolute path) and
 * copies content into memory; then it closes file. File name is saved in data.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_file(&aData, [filename fileSystemRepresentation], 1);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    [self setFilename:[filename lastPathComponent]];
    
    return self;
}

- (id) initWithContentsOfFileNoCopy:(NSString *)filename
#warning Not yet supported as of 1.1.x
// Can raise a GPGException; in this case, a release is sent to self
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_file(&aData, [filename fileSystemRepresentation], 0);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    [self setFilename:[filename lastPathComponent]];
    
    return self;
}

- (id) initWithContentsOfFile:(NSString *)filename atOffset:(unsigned long long)offset length:(unsigned long long)length
/*"
 * Immediately opens file and copies partial content into memory; then it
 * closes file. File name is saved in data.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    // We don't provide a method to match the case where filename is NULL
    // and filePtr (FILE *) is not NULL (both arguments are exclusive),
    // because we generally don't manipulate FILE * types in Cocoa.
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_filepart(&aData, [filename fileSystemRepresentation], NULL, offset, length);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    [self setFilename:[filename lastPathComponent]];

    return self;
}

// We don't support gpgme_data_new_from_stream(), because there is
// no STREAM handling in Cocoa, yet(?).
// Maybe in Panther with NSStream?

- (id) initWithFileHandle:(NSFileHandle *)fileHandle
/*"
 * Uses fileHandle to read from (if used as an input data object) and write to
 * (if used as an output data object). fileHandle is retained.
 *
 * When using the data object as an input buffer, the method might read a bit
 * more from the file handle than is actually needed by the crypto engine in
 * the desired operation because of internal buffering.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    gpgme_data_t	aData;
    gpgme_error_t	anError = gpgme_data_new_from_fd(&aData, [fileHandle fileDescriptor]);

    if(anError != GPG_ERR_NO_ERROR){
        [self release];
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
    }
    self = [self initWithInternalRepresentation:aData];
    ((GPGData *)self)->_objectReference = [fileHandle retain];

    return self;
}

- (void) dealloc
{
    gpgme_data_t	cachedData = _data;

    if(_callbacks != NULL)
        NSZoneFree([self zone], _callbacks);
    // If _callbacks is not NULL, it means that _objectReference was a non-retained dataSource
    else if(_objectReference != nil)
        [_objectReference release];
    [super dealloc];

    // We could have a problem here if we set ourself as callback
    // and _data is deallocated later than us!!!
    // This shouldn't happen, but who knows...
    if(cachedData != NULL)
        gpgme_data_release(cachedData);
}

#if 0
- (id) copyWithZone:(NSZone *)zone
{
    GPGData	*aCopy = nil;
    
    switch([self type]){
        case GPGDataTypeNone:
            aCopy = [[[self class] allocWithZone:zone] init];
            break;
        case GPGDataTypeData:
            if(_retainedData != nil){
                NSMutableData	*copiedData = [_retainedData mutableCopyWithZone:zone];
                
                aCopy = [[[self class] allocWithZone:zone] initWithDataNoCopy:copiedData];
                [copiedData release];
            }
            else
                aCopy = [[[self class] allocWithZone:zone] initWithData:[self data]]; // WARNING: this rewinds myself and reads until EOF!
            break;
        case GPGDataTypeFileHandle:
            // We don't provide a way in GPGME to create such data types
            [NSException raise:NSInternalInconsistencyException format:@"### Unsupported GPGData type %d", [self type]];
            break;
        case GPGDataTypeFile:
            // There is no way to know which inititializer was called!
            [NSException raise:NSInternalInconsistencyException format:@"### Unsupported GPGData type %d", [self type]];
            break;
        case GPGDataTypeDataSource:
            aCopy = [[[self class] allocWithZone:zone] initWithDataSource:_dataSource];
            [aCopy rewind]; // This also rewinds myself!
            break;
        default:
            [NSException raise:NSInternalInconsistencyException format:@"### Unknown GPGData type %d", [self type]];
    }
    
    return aCopy;
}
#endif

- (GPGDataEncoding) encoding
/*"
 * Returns the encoding of the data object.
"*/
{
    GPGDataEncoding	encoding = gpgme_data_get_encoding(_data);

    return encoding;
}

- (void) setEncoding:(GPGDataEncoding)encoding
/*"
 * Sets the encoding of the data object.
 *
 * Can raise a #GPGException.
"*/
{
    gpgme_error_t	anError = gpgme_data_set_encoding(_data, encoding);

    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (unsigned long long) seekToFileOffset:(unsigned long long)offset offsetType:(GPGDataOffsetType)offsetType
/*"
 * Sets the current position from where the next read or write starts in the
 * data object to offset, relativ to offsetType. Returns the resulting file
 * position, measured in bytes from the beginning of the data object. You can
 * use this feature together with #GPGDataCurrentPosition to read the current
 * read/write position.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    off_t	newPosition = gpgme_data_seek(_data, offset, offsetType);

    if(newPosition < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];

    return newPosition;
}

- (NSData *) readDataOfLength:(unsigned long long)length
/*"
 * Reads up to length bytes and returns them wrapped in a #NSData. Reading
 * starts from the current position. Returned data has the appropriate size,
 * smaller or equal to length. Returns nil when there isn't anything more to
 * read (EOF).
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    NSMutableData	*readData = [NSMutableData dataWithLength:length];
    ssize_t			aReadLength = gpgme_data_read(_data, [readData mutableBytes], length);
    
    if(aReadLength == 0)
        return nil;
    if(aReadLength < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];
    [readData setLength:aReadLength];

    return readData;
}

- (unsigned long long) writeData:(NSData *)data
/*"
 * Writes data bytes by copying them. Writing starts from the current
 * position. Returns the number of bytes written.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    ssize_t writtenByteCount = gpgme_data_write(_data, [data bytes], [data length]);
    
    if(writtenByteCount < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];

    return writtenByteCount;
}

- (NSString *) filename
/*"
 * Return the filename associated with the data object, or nil if there is none
 * or if there is an error.
"*/
{
    const char	*aCString = gpgme_data_get_file_name(_data); // Returns original string -> make a copy
    
    return GPGStringFromChars(aCString);
}

- (void) setFilename:(NSString *)filename
/*"
 * Set the filename associated with the data object. The filename will be stored
 * in the output when encrypting or signing the data and will be returned to the
 * user when decrypting or verifying the output data.
 *
 * Can raise a #GPGException of type #GPGError_ENOMEM if not enough memory is 
 * available.
"*/
{
    const char      *aCString = (filename != nil ? [filename fileSystemRepresentation] : NULL);    
    gpgme_error_t	anError = gpgme_data_set_file_name(_data, aCString); // Will duplicate string
    
    if(anError != GPG_ERR_NO_ERROR)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

@end


@implementation GPGData(GPGExtensions)

- (id) initWithString:(NSString *)string
/*"
 * Convenience method. Gets data from string using UTF8 encoding, and invokes
 * #{-initWithData:}.
 *
 * Can raise a #GPGException; in this case, a #release is sent to self.
"*/
{
    NSData	*data = [string dataUsingEncoding:NSUTF8StringEncoding];

    return [self initWithData:data];
}

- (NSString *) string
/*"
 * Convenience method. Returns a copy of all data as string, using UTF8 string
 * encoding (or ISOLatin1 if it cannot be decoded as UTF8). It rewinds
 * receiver, then reads data until EOF, and returns a string initialized with
 * it.
 *
 * Invoking this method has sense only when you know that data corresponds to
 * a string!
 *
 * Can raise a #GPGException.
"*/
{
    NSData	*data = [self data];

    return GPGStringFromChars([data bytes]);
}

- (unsigned long long) availableDataLength
/*"
 * Returns the amount of bytes available without changing the read pointer.
 * This is not supported by all types of data objects.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * If end of data object is reached or no data is currently available, it
 * returns 0. To know if there are more bytes to read, you must invoke
 * #{-isAtEnd}.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    ssize_t	availableDataLength = gpgme_data_read(_data, NULL, 0);

    if(availableDataLength < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];

    return availableDataLength;
}

- (unsigned long long) length
/*"
 * Convenience method. Returns length of all data. It rewinds receiver, then
 * reads available data length and returns it. Read pointer is reset.
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
 * Returns YES if there are no more bytes to read (EOF). Read pointer is not
 * moved.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    ssize_t	availableDataLength = gpgme_data_read(_data, NULL, 0);

    if(availableDataLength < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];
    else if(availableDataLength == 0)
        return YES;
    
    return NO;
}

- (NSData *) availableData
/*"
 * Returns a copy of data, read from current position, up to end of data.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    size_t			bufferSize = NSPageSize();
    NSZone			*aZone = NSDefaultMallocZone();
    char			*bufferPtr = (char *)NSZoneMalloc(aZone, bufferSize);
    NSMutableData	*readData = [NSMutableData dataWithCapacity:bufferSize];
    ssize_t			aReadLength;
    
    do{
        aReadLength = gpgme_data_read(_data, bufferPtr, bufferSize);
        
        if(aReadLength > 0)
            [readData appendBytes:bufferPtr length:aReadLength];
    }while(aReadLength > 0);

    NSZoneFree(aZone, bufferPtr);
    if(aReadLength < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];

    return readData;
}

- (NSData *) data
/*"
 * Convenience method. Returns a copy of all data. It rewinds receiver, then
 * reads data until EOF, and returns it.
 *
 * If this method is not supported, a #GPGException is raised, with error
 * #GPGErrorInvalidType.
 *
 * Can raise a #GPGException.
"*/
{
    [self rewind];

    return [self availableData];
}

- (void) rewind
/*"
 * Prepares data in a way that the next call to #{-readDataOfLength:} or
 * #{-writeData:} starts at the beginning of the data.
 *
 * Can raise a #GPGException of type #{GPGError_E*}.
"*/
{
    off_t	newPosition = gpgme_data_seek(_data, 0, GPGDataStartPosition);

    if(newPosition < 0)
        [[NSException exceptionWithGPGError:gpgme_err_make_from_errno(GPG_MacGPGMEFrameworkErrorSource, errno) userInfo:nil] raise];
}

@end


@implementation GPGData(GPGInternals)

- (gpgme_data_t) gpgmeData
{
    return _data;
}

@end


// We need to write this fake implementation (not compiled!)
// just to force autodoc to take our comments in account!
#ifdef FAKE_IMPLEMENTATION_FOR_AUTODOC
@implementation NSObject(GPGDataSource)
/*"
 * This category declares methods that need to be implemented by
 * #GPGData data sources. Data sources can be readable or writable.
"*/
- (NSData *) data:(GPGData *)data readDataOfLength:(unsigned long long)maxLength
/*"
 * Reads up to maxLength bytes of data and returns it. Returning an empty data
 * or nil means that there is nothing more to read (EOF). Only required for
 * input data objects.
 *
 * Reading must be performed from the current position.
 *
 * In case of error, raise a #GPGException of type #{GPGError_E*}.
 *
 * Returned data will be copied.
"*/
{}

- (unsigned long long) data:(GPGData *)data writeData:(NSData *)writeData
/*"
 * Writes writeData from the current position. Returns the number of
 * bytes written. Only required for output data objects.
 *
 * In case of error, raise a #GPGException of type #{GPGError_E*}.
"*/
{}

- (unsigned long long) data:(GPGData *)data seekToFileOffset:(unsigned long long)fileOffset offsetType:(GPGDataOffsetType)offsetType
/*"
 * Changes the read/write position according to fileOffset and offsetType. Returns the new
 * absolute position. Optional method.
 *
 * In case of error, raise a #GPGException of type #{GPGError_E*}.
"*/
{}

- (void) dataRelease:(GPGData *)data
/*"
 * Releases internal resources owned by the data source. Optional method.
"*/
{}
@end
#endif
