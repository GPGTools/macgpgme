//
//  GPGController.h
//  GPGTester
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
//  More info at <http://macgpg.sourceforge.net/> or <macgpg@rbisland.cx> or
//  <davelopper@users.sourceforge.net>.
//

#import <AppKit/AppKit.h>

@interface Controller : NSObject
{
    NSArray					*keys;
    
    IBOutlet NSTableView	*keyTableView;
    IBOutlet NSTableView	*userIDTableView;
    IBOutlet NSTableView	*subkeyTableView;
    IBOutlet NSTextField	*searchPatternTextField;
    IBOutlet NSTextView		*xmlTextView;
    IBOutlet NSBox			*mainKeyBox;
    IBOutlet NSTextField	*algorithmTextField;
    IBOutlet NSTextField	*lengthTextField;
    IBOutlet NSTextField	*validityTextField;
    IBOutlet NSButtonCell	*hasSecretSwitch;
    IBOutlet NSButtonCell	*canExcryptSwitch;
    IBOutlet NSButtonCell	*canSignSwitch;
    IBOutlet NSButtonCell	*canCertifySwitch;
    IBOutlet NSButtonCell	*isRevokedSwitch;
    IBOutlet NSButtonCell	*isInvalidSwitch;
    IBOutlet NSButtonCell	*hasExpiredSwitch;
    IBOutlet NSButtonCell	*isDisabledSwitch;
    IBOutlet NSTextField	*ownerTrustField;
    IBOutlet NSTextField	*trustLevelField;
    IBOutlet NSTextField	*trustTypeTextField;
    
    IBOutlet NSTextField	*passphraseDescriptionTextField;
    IBOutlet NSTextField	*passphraseTextField;
    IBOutlet NSPanel		*passphrasePanel;

    IBOutlet NSTextField	*encryptionInputFilenameTextField;
    IBOutlet NSButtonCell	*encryptionArmoredSwitch;
    IBOutlet NSTextField	*encryptionOutputFilenameTextField;
    IBOutlet NSPanel		*encryptionPanel;

    IBOutlet NSTextField	*signingInputFilenameTextField;
    IBOutlet NSButtonCell	*signingArmoredSwitch;
    IBOutlet NSButtonCell	*signingDetachedSwitch;
    IBOutlet NSTextField	*signingOutputFilenameTextField;
    IBOutlet NSPanel		*signingPanel;

    IBOutlet NSButtonCell	*deleteSwitch;
    IBOutlet NSButton		*deleteButton;
    
    unsigned				idleCounter;
    NSArray					*idleImages;
    IBOutlet NSImageView	*idleImageView;
}

- (IBAction) searchKeys:(id)sender;

- (IBAction) encrypt:(id)sender;
- (IBAction) askInputFileForEncryption:(id)sender;
- (IBAction) askOutputFileForEncryption:(id)sender;

- (IBAction) decrypt:(id)sender;

- (IBAction) sign:(id)sender;
- (IBAction) askInputFileForSigning:(id)sender;
- (IBAction) askOutputFileForSigning:(id)sender;

- (IBAction) verify:(id)sender;
- (IBAction) verifyDetachedSignature:(id)sender;

- (IBAction) export:(id)sender;
- (IBAction) import:(id)sender;

- (IBAction) deleteKey:(id)sender;

- (IBAction) ok:(id)sender;
- (IBAction) cancel:(id)sender;

@end
