//
//  GPGData.m
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

#import "GPGData.h"
#import "GPGExceptions.h"
#import <Foundation/Foundation.h>
#import <gpgme.h>


#define _data		((GpgmeData)_internalRepresentation)
#define _dataPtr	((GpgmeData *)&_internalRepresentation)
#define CHECK_STATE	do { if(_data == NULL)                                       \
                             [NSException raise:NSGenericException               \
                                         format:@"After -[GPGData data] has been called, instance can't respond to any other message than -release or -dealloc."]; \
                    } while(0)


@implementation GPGData

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

static int readCallback(void *object, char *destinationBuffer, size_t destinationBufferSize, size_t *readLength)
{
    // Returns whether it could read anything or not (EOF)
    NSData	*readData = [((GPGData *)object)->_dataSource data:((GPGData *)object) readLength:destinationBufferSize];

    if(readData == nil)
        return 0;
    else{
        *readLength = [readData length];
        NSCAssert(*readLength <= destinationBufferSize, @"Datasource may not return more bytes that given capacity!");
        [readData getBytes:destinationBuffer];
        return 1;
    }
}

- (id) initWithDataSource:(id)dataSource
/*"
 * dataSource must respond to selector #{data:readLength:}. dataSource is not
 * retained. Data can only be read.
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
// Not yet supported as of 0.2.3
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
    // and filePtr (FILE *) is not NULL (both arguments are exclusive).
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

    // We can have a problem here if we set ourself as callback
    // and _data is dealloced later than us!!!
    // This shouldn't happen, but who knows...
    if(cachedData != NULL)
        gpgme_data_release(cachedData);
}

- (NSData *) data
/*"
 * Returns a copy of data. #WARNING: after having called this method, instance can't
 * respond to any other message; it should be released; it will raise an
 * #NSGenericException!!!
 *
 * Returns nil if it couldn't allocate enough memory.
"*/
{
    size_t	aReadLength;
    char	*aBuffer;
    NSData	*returnedData = nil;

    CHECK_STATE;
    aBuffer = gpgme_data_release_and_get_mem(_data, &aReadLength);
    _data = NULL;
    if(aBuffer != NULL){
        returnedData = [NSData dataWithBytes:aBuffer length:aReadLength];
        free(aBuffer);
    }
    
    return returnedData;
}

- (GPGDataType) type
{
    CHECK_STATE;

    return gpgme_data_get_type(_data);
}

- (void) rewind
/*"
 * Prepares data in a way that the next call to #{-readDataOfLength:} starts at
 * the beginning of the data. This has to be done for all types of GPGData objects.
 *
 * Can raise a #GPGException.
"*/
{
    GpgmeError	anError;
    
    CHECK_STATE;
    anError = gpgme_data_rewind(_data);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

- (NSData *) readDataOfLength:(unsigned int)length
/*"
 * Reading starts from the current position. Returned data has the
 * appropriate size, smaller or equal to length. Returns nil when there isn't
 * anything more to read. Read data should be copied, not referenced.
 *
 * Can raise a #GPGException (but never a #GPGErrorEOF one).
"*/
{
    GpgmeError		anError;
    NSMutableData	*readData;
    size_t			aReadLength;
    
    CHECK_STATE;
    readData = [NSMutableData data];
    [readData setLength:length];
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
    GpgmeError	anError;
    
    CHECK_STATE;
    anError = gpgme_data_write(_data, [data bytes], [data length]);
    if(anError != GPGME_No_Error)
        [[NSException exceptionWithGPGError:anError userInfo:nil] raise];
}

/*
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
}*/
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
 * Returned data length must have a length smaller or equal to maxLength. If
 * there is nothing more to read, return nil. Read data will be copied.
"*/
{}
@end
#endif
