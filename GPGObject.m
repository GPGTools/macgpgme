//
//  GPGObject.m
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

#import "GPGObject.h"
#import <Foundation/Foundation.h>


@implementation GPGObject

/*"
 This abstract class takes care of uniquing instances
 against %gpgme internal structures. It is the base class for
 all classes wrapping %gpgme structures.
"*/

static NSMapTable	*mapTable = NULL;
static NSLock		*mapTableLock = nil;

+ (void) initialize
{
    [super initialize];
    if(mapTable == NULL){
        mapTable = NSCreateMapTable(NSNonOwnedPointerMapKeyCallBacks, NSNonRetainedObjectMapValueCallBacks, 100);
        mapTableLock = [[NSLock alloc] init];
    }
}

- (id) initWithInternalRepresentation:(void *)aPtr
/*"
 Default initializer.

 All subclasses must call this method.
 Can return another object than the one which received the message!
 In this case the original object is released.
"*/
{
    NSParameterAssert(aPtr != NULL);
    
    if(self = [super init]){
        id	anExistingObject = NSMapGet(mapTable, aPtr);

        if(anExistingObject != nil){
            [self release];
            self = [anExistingObject retain]; // We MUST call -retain, because there was an +alloc, and retainCount must augment
        }
        else{
            _internalRepresentation = aPtr;
            [mapTableLock lock];
            NSMapInsertKnownAbsent(mapTable, _internalRepresentation, self);
            [mapTableLock unlock];
        }
    }

    return self;
}

- (void) dealloc
/*"
#WARNING: %_internalRepresentation pointer MUST still be valid when
#{-[GPGObject dealloc]} method is called!!!
 "*/
{
    if(_internalRepresentation != NULL){
        [mapTableLock lock];
        NSMapRemove(mapTable, _internalRepresentation);
        [mapTableLock unlock];
    }
    
    [super dealloc];
}

@end
