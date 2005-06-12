//
//  GPGAsyncHelper.h
//  MacGPGME
//
//  Created by Dave Lopper on Mon Apr 12 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import <Foundation/Foundation.h>


@class GPGContext;


@interface GPGAsyncHelper : NSObject {
    NSLock			*_dataLock;
    NSConditionLock	*_runSemaphore;
    NSMapTable		*_paramsPerFd;
    NSMutableSet	*_contexts;
}

+ (GPGAsyncHelper *) sharedInstance;

- (void) prepareAsyncOperationInContext:(GPGContext *)context;

@end
