//
//  GPGObject.m
//  GPGME
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

#include <GPGME/GPGObject.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


@implementation GPGObject

/*"
 * This abstract class takes care of uniquing instances
 * against %gpgme internal structures. It is the base class for
 * all classes wrapping %gpgme structures.
"*/

static NSMapTable	*mapTable = NULL;
static NSLock		*mapTableLock = nil;

+ (void) initialize
/*"
 * Initializes %gpgme library sub-systems and insures that Cocoa is ready for multithreading.
 * Can be invoked multiple times, initialization is done only once.
"*/
{
    [super initialize];
    if(mapTable == NULL){
        NSObject	*aThreadStarter = [[NSObject alloc] init];	

        mapTable = NSCreateMapTable(NSNonOwnedPointerMapKeyCallBacks, NSNonRetainedObjectMapValueCallBacks, 100);
        mapTableLock = [[NSLock alloc] init];
    
        // gpgme library uses pthreads; to avoid any problems with
        // Foundation's NSThreads, we must ensure that that at least
        // one NSThread has been created, that's why we create a dummy
        // thread before doing anything with gpgme.
        [NSThread detachNewThreadSelector:@selector(release) toTarget:aThreadStarter withObject:nil];

        setlocale (LC_ALL, "");
        // Let's initialize libgpgme sub-systems now.
        NSAssert(gpgme_check_version(NULL) != NULL, @"### Unable to initialize gpgme sub-systems.");
        // Let's initialize default locale; we don't use that possibility in GPGME.framework yet
        gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
        gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
    }
}

+ (BOOL) needsPointerUniquing
{
    return NO;
}

- (id) initWithInternalRepresentation:(void *)aPtr
/*"
 * Default initializer.
 *
 * All subclasses must call this method.
 * Can return another object than the one which received the message!
 * In this case the original object is released.
"*/
{
    BOOL	needsPointerUniquing = [[self class] needsPointerUniquing];

    NSAssert(!needsPointerUniquing || aPtr != NULL, @"### Cannot map wrapper to a NULL pointer");
    
    if(self = [super init]){
        id	anExistingObject = nil;

        if(needsPointerUniquing){
            [mapTableLock lock];
            anExistingObject = NSMapGet(mapTable, aPtr);
            [mapTableLock unlock];
        }

        if(anExistingObject != nil){
            [self release];
            self = [anExistingObject retain]; // We MUST call -retain, because there was an +alloc, and retainCount must augment
        }
        else{
            _internalRepresentation = aPtr;
            if(needsPointerUniquing){
                [mapTableLock lock];
                NSMapInsertKnownAbsent(mapTable, _internalRepresentation, self);
                [mapTableLock unlock];
            }
        }
    }

    return self;
}

- (void) dealloc
/*"
 * #WARNING: %_internalRepresentation pointer MUST still be valid when
 * #{-[GPGObject dealloc]} method is called!!!
"*/
{
    if([[self class] needsPointerUniquing]){
        if(_internalRepresentation != NULL){
            [mapTableLock lock];
            NSMapRemove(mapTable, _internalRepresentation);
            [mapTableLock unlock];
        }
    }
    else{
        if(_internalRepresentation != NULL){
            // Free pointer?
        }
    }
    
    [super dealloc];
}

+ (BOOL) accessInstanceVariablesDirectly
{
    return NO;
}

@end
