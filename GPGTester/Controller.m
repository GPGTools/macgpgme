//
//  Controller.m
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

#import "Controller.h"
#import <GPGME/GPGME.h>
#import <GPGME/GPGEngine.h>


@implementation Controller

- (void) awakeFromNib
{
    NSString	*aString;
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(idle:) name:GPGIdleNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(keyringChanged:) name:GPGKeyringChangedNotification object:nil];
    idleImages = [[NSArray alloc] initWithObjects:[NSImage imageNamed:@"idle1"], [NSImage imageNamed:@"idle2"], [NSImage imageNamed:@"idle3"], [NSImage imageNamed:@"idle4"], nil];
    aString = [NSString stringWithFormat:@"Testing engine...\n%@\nEngine info:\n%@", GPGErrorDescription(GPGCheckEngine()), GPGEngineInfoAsXMLString()];
    [xmlTextView setString:aString];
}

- (void) dealloc
{
    [[keyTableView window] release];
    [passphrasePanel release];
    [encryptionPanel release];
    [signingPanel release];
    [keys release];
    [idleImages release];
    
    [super dealloc];
}

- (void) idle:(NSNotification *)notification
{
    [idleImageView setImage:[idleImages objectAtIndex:(idleCounter++ % 4)]];
    [idleImageView display];
}

- (GPGRecipients *) selectedRecipients
{
    if([keyTableView numberOfSelectedRows] <= 0)
        return nil;
    else{
        GPGRecipients	*recipients = [[GPGRecipients alloc] init];
        NSEnumerator	*anEnum = [keyTableView selectedRowEnumerator];
        NSNumber		*aRow;

        while(aRow = [anEnum nextObject]){
            GPGKey	*aKey = [keys objectAtIndex:[aRow intValue]];

            [recipients addName:[aKey userID]];
        }

        return [recipients autorelease];
    }
}

- (IBAction) searchKeys:(id)sender
{
    GPGContext	*aContext = [[GPGContext alloc] init];
    
    [keys release];
    keys = nil;
    keys = [[[aContext keyEnumeratorForSearchPattern:[searchPatternTextField stringValue] secretKeysOnly:NO] allObjects] retain];
    [aContext release];
    [keyTableView noteNumberOfRowsChanged];
    [keyTableView reloadData];
}

- (int) numberOfRowsInTableView:(NSTableView *)tableView
{
    if(tableView == keyTableView)
        return [keys count];
    else{
        int	selectedRow = [keyTableView selectedRow];

        if(selectedRow >= 0){
            GPGKey	*selectedKey = [keys objectAtIndex:selectedRow];

            if(tableView == userIDTableView)
                return [[selectedKey userIDs] count];
            else /* subkeyTableView */
                return [[selectedKey subkeysKeyIDs] count];
        }
        else
            return 0;
    }
}

- (id) tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(int)row
{
    if(tableView == keyTableView)
        return [[keys objectAtIndex:row] performSelector:NSSelectorFromString([tableColumn identifier])];
    else{
        int	selectedRow = [keyTableView selectedRow];

        if(selectedRow >= 0){
            return [[[keys objectAtIndex:selectedRow] performSelector:NSSelectorFromString([tableColumn identifier])] objectAtIndex:row];
        }
        else
            return nil; // Shouldn't happen
    }
}

- (void) tableViewSelectionDidChange:(NSNotification *)notification
{
    if([notification object] == keyTableView){
        int	selectedRow = [keyTableView selectedRow];
        
        if(selectedRow >= 0){
            GPGKey	*selectedKey = [keys objectAtIndex:selectedRow];
            NSLog(@"%@", [selectedKey expirationDate]);
    
            [xmlTextView setString:[selectedKey descriptionAsXMLString]];
    
            [mainKeyBox setTitle:[selectedKey userID]];
    
            [algorithmTextField setIntValue:[selectedKey algorithm]];
            [lengthTextField setIntValue:[selectedKey length]];
            [validityTextField setIntValue:[selectedKey validity]];
    
            [hasSecretSwitch setState:[selectedKey hasSecretPart]];
            [canExcryptSwitch setState:[selectedKey canEncrypt]];
            [canSignSwitch setState:[selectedKey canSign]];
            [canCertifySwitch setState:[selectedKey canCertify]];
    
            [isRevokedSwitch setState:[selectedKey isKeyRevoked]];
            [isInvalidSwitch setState:[selectedKey isKeyInvalid]];
            [hasExpiredSwitch setState:[selectedKey hasKeyExpired]];
            [isDisabledSwitch setState:[selectedKey isKeyDisabled]];
    
            if(selectedKey != nil){
                GPGContext		*aContext = [[GPGContext alloc] init];
                GPGTrustItem	*trustItem;
    
                trustItem = [[[aContext trustItemEnumeratorForSearchPattern:[selectedKey userID] maximumLevel:100] allObjects] lastObject];
                [aContext release];
    
                [ownerTrustField setIntValue:[trustItem validity]];
                [trustLevelField setIntValue:[trustItem level]];
                [trustTypeTextField setIntValue:[trustItem type]];
                [deleteButton setEnabled:YES];
            }
            else{
                [ownerTrustField setIntValue:0];
                [trustLevelField setIntValue:0];
                [trustTypeTextField setIntValue:0];
                [deleteButton setEnabled:NO];
            }
        }
        else{
            [xmlTextView setString:@""];
            [mainKeyBox setTitle:@""];
            [algorithmTextField setIntValue:0];
            [lengthTextField setIntValue:0];
            [validityTextField setIntValue:0];
    
            [hasSecretSwitch setState:NO];
            [canExcryptSwitch setState:NO];
            [canSignSwitch setState:NO];
            [canCertifySwitch setState:NO];
    
            [isRevokedSwitch setState:NO];
            [isInvalidSwitch setState:NO];
            [hasExpiredSwitch setState:NO];
            [isDisabledSwitch setState:NO];
            
            [ownerTrustField setIntValue:0];
            [trustLevelField setIntValue:0];
            [trustTypeTextField setIntValue:0];
            [deleteButton setEnabled:NO];
        }
        [subkeyTableView noteNumberOfRowsChanged];
        [subkeyTableView reloadData];
        [userIDTableView noteNumberOfRowsChanged];
        [userIDTableView reloadData];
    }
}

- (IBAction) ok:(id)sender
{
    [[sender window] orderOut:sender];
    [NSApp stopModalWithCode:NSAlertDefaultReturn];
}

- (IBAction) cancel:(id)sender
{
    [[sender window] orderOut:sender];
    [NSApp stopModalWithCode:NSAlertAlternateReturn];
}

- (NSString *) context:(GPGContext *)context passphraseForDescription:(NSString *)description userInfo:(NSMutableDictionary *)userInfo
{
    [passphraseDescriptionTextField setStringValue:description];
    [passphraseTextField setStringValue:@""];
    [passphrasePanel orderFront:nil];

    if([NSApp runModalForWindow:passphrasePanel] == NSAlertDefaultReturn){
        NSString	*passphrase = [[passphraseTextField stringValue] copy];

        [passphraseTextField setStringValue:@""];
        return [passphrase autorelease];
    }
    else
        return nil;
}

- (void) decryptFile:(NSString *)inputFilename
{
    GPGContext	*aContext = [[GPGContext alloc] init];
    GPGData		*decryptedData = nil, *inputData = nil;
    NSSavePanel	*savePanel;

    [aContext setPassphraseDelegate:self];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(contextOperationIsProgressing:) name:GPGProgressNotification object:aContext];
    NS_DURING
        inputData = [[GPGData alloc] initWithContentsOfFile:inputFilename];
        decryptedData = [[aContext decryptedData:inputData] retain];

        NSLog(@"Notations: %@", [aContext notationsAsXMLString]);
        [inputData release];
    NS_HANDLER
        NSLog(@"Exception userInfo: %@", [localException userInfo]);
        NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
        [aContext release];
        [inputData release];
        [decryptedData release];
        return;
    NS_ENDHANDLER

    savePanel = [NSSavePanel savePanel];
    [savePanel setTreatsFilePackagesAsDirectories:YES];

    if([savePanel runModal] == NSOKButton){
        [[decryptedData data] writeToFile:[savePanel filename] atomically:NO];
    }
    [[NSNotificationCenter defaultCenter] removeObserver:self name:GPGProgressNotification object:aContext];
    [aContext release];
    [decryptedData release];
}

- (IBAction) decrypt:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        [self decryptFile:[openPanel filename]];
    }
}

- (void) contextOperationIsProgressing:(NSNotification *)notification
{
    NSDictionary	*userInfo = [notification userInfo];
    
    NSLog(@"%@ (%@): %@/%@", [userInfo objectForKey:@"description"], [userInfo objectForKey:@"type"], [userInfo objectForKey:@"current"], [userInfo objectForKey:@"total"]);
}

- (IBAction) encrypt:(id)sender
{
    if([NSApp runModalForWindow:encryptionPanel] == NSOKButton){
        GPGContext	*aContext;
        GPGData		*inputData, *outputData;
        volatile BOOL	allRecipientsAreValid;

        if([[encryptionInputFilenameTextField stringValue] length] == 0 || [[encryptionOutputFilenameTextField stringValue] length] == 0){
            NSRunAlertPanel(@"Error", @"You need to give a filename for input and output files.", nil, nil, nil);
            return;
        }

        aContext = [[GPGContext alloc] init];
        [aContext setUsesArmor:[encryptionArmoredSwitch state]];
//[aContext addSigner:[keys objectAtIndex:2]]; // encrypt+sign is from now on supported
        inputData = [[GPGData alloc] initWithContentsOfFile:[encryptionInputFilenameTextField stringValue]];

        NS_DURING
            outputData = [aContext encryptedData:inputData forRecipients:[self selectedRecipients] allRecipientsAreValid:(BOOL *)&allRecipientsAreValid];
        NS_HANDLER
            outputData = nil;
            NSLog(@"Exception userInfo: %@", [localException userInfo]);
            NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
        NS_ENDHANDLER

        if(outputData != nil){
            if(!allRecipientsAreValid)
                NSRunAlertPanel(@"Warning", @"Some recipients are not valid, and they have not been used for encryption.\n\n%@", nil, nil, nil, [aContext statusAsXMLString]);
            [[outputData data] writeToFile:[encryptionOutputFilenameTextField stringValue] atomically:NO];
        }
        [inputData release];
        [aContext release];
    }
}

- (IBAction) askInputFileForEncryption:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        [encryptionInputFilenameTextField setStringValue:[openPanel filename]];
    }
}

- (IBAction) askOutputFileForEncryption:(id)sender
{
    NSSavePanel	*savePanel = [NSSavePanel savePanel];
    
    [savePanel setTreatsFilePackagesAsDirectories:YES];

    if([savePanel runModal] == NSOKButton){
        [encryptionOutputFilenameTextField setStringValue:[savePanel filename]];
    }
}

- (BOOL) validateMenuItem:(id <NSMenuItem>)menuItem
{
    if([menuItem action] == @selector(export:) || [menuItem action] == @selector(encrypt:) || [menuItem action] == @selector(sign:))
        return [keyTableView numberOfSelectedRows] > 0;
    else
        return YES;
}

- (IBAction) export:(id)sender
{
    GPGContext	*aContext = nil;

    NS_DURING
        NSSavePanel	*savePanel;
        GPGData		*exportedData;

        aContext = [[GPGContext alloc] init];
        [aContext setUsesArmor:YES];
        exportedData = [aContext exportedKeysForRecipients:[self selectedRecipients]];
        
        savePanel = [NSSavePanel savePanel];

        [savePanel setTreatsFilePackagesAsDirectories:YES];

        if([savePanel runModal] == NSOKButton){
            [[exportedData data] writeToFile:[savePanel filename] atomically:NO];
        }
    NS_HANDLER
        NSLog(@"Exception userInfo: %@", [localException userInfo]);
        NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
    NS_ENDHANDLER
    [aContext release];
}

- (IBAction) import:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        GPGContext	*aContext = nil;
        GPGData		*importedData;

        NS_DURING
            aContext = [[GPGContext alloc] init];
            importedData = [[GPGData alloc] initWithContentsOfFile:[openPanel filename]];
            [aContext importKeyData:importedData];

        NS_HANDLER
            NSLog(@"Exception userInfo: %@", [localException userInfo]);
            NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
        NS_ENDHANDLER
        [aContext release];
        [importedData release];
    }
}

- (IBAction) askInputFileForSigning:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        [signingInputFilenameTextField setStringValue:[openPanel filename]];
    }
}

- (IBAction) askOutputFileForSigning:(id)sender
{
    NSSavePanel	*savePanel = [NSSavePanel savePanel];

    [savePanel setTreatsFilePackagesAsDirectories:YES];

    if([savePanel runModal] == NSOKButton){
        [signingOutputFilenameTextField setStringValue:[savePanel filename]];
    }
}

- (IBAction) sign:(id)sender
{
    if([NSApp runModalForWindow:signingPanel] == NSOKButton){
        GPGContext	*aContext;
        GPGData		*inputData, *outputData = nil;

        if([[signingInputFilenameTextField stringValue] length] == 0 || [[signingOutputFilenameTextField stringValue] length] == 0){
            NSRunAlertPanel(@"Error", @"You need to give a filename for input and output files.", nil, nil, nil);
            return;
        }

        aContext = [[GPGContext alloc] init];
        [aContext setPassphraseDelegate:self];
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(contextOperationIsProgressing:) name:GPGProgressNotification object:aContext];
        [aContext setUsesArmor:[signingArmoredSwitch state]];
        inputData = [[GPGData alloc] initWithContentsOfFile:[signingInputFilenameTextField stringValue]];

        NS_DURING
            NSEnumerator	*anEnum = [keyTableView selectedRowEnumerator];
            NSNumber		*aRow;

            while(aRow = [anEnum nextObject])
                [aContext addSignerKey:[keys objectAtIndex:[aRow intValue]]];
            
            outputData = [aContext signedData:inputData signatureMode:[signingDetachedSwitch state]];
        NS_HANDLER
            outputData = nil;
            NSLog(@"Exception userInfo: %@", [localException userInfo]);
            NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
        NS_ENDHANDLER

        if(outputData != nil){
            [[outputData data] writeToFile:[signingOutputFilenameTextField stringValue] atomically:NO];
        }
        [[NSNotificationCenter defaultCenter] removeObserver:self name:GPGProgressNotification object:aContext];
        [inputData release];
        [aContext release];
    }
}

- (NSString *) stringFromSignatureStatus:(GPGSignatureStatus)status
{
    switch(status){
        case GPGSignatureStatusNone:
            return @"No status!";
        case GPGSignatureStatusGood:
            return @"OK";
        case GPGSignatureStatusBad:
            return @"BAD";
        case GPGSignatureStatusNoKey:
            return @"No public key";
        case GPGSignatureStatusNoSignature:
            return @"No signature!";
        case GPGSignatureStatusError:
            return @"Error!";
        case GPGSignatureStatusDifferent:
            return @"Different statuses";
        default:
            return [NSString stringWithFormat:@"Unknown result: %d", status];
    }
}

- (void) authenticateFile:(NSString *)inputFilename againstSignatureFile:(NSString *)signatureFilename
{
    GPGContext	*aContext = [[GPGContext alloc] init];
    GPGData		*inputData = nil, *signatureData = nil;

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(contextOperationIsProgressing:) name:GPGProgressNotification object:aContext];
    NS_DURING
        GPGSignatureStatus	aStatus;
        NSString			*statusString = nil;
        
        inputData = [[GPGData alloc] initWithContentsOfFile:inputFilename];
        if(signatureFilename != nil)
            signatureData = [[GPGData alloc] initWithContentsOfFile:signatureFilename];
        if(signatureData != nil)
            aStatus = [aContext verifySignatureData:signatureData againstData:inputData];
        else
            aStatus = [aContext verifySignedData:inputData];
        statusString = [self stringFromSignatureStatus:aStatus];
        {
            int	i;

            for(i = 0; ; i++){
                GPGKey	*aKey = [aContext keyOfSignatureAtIndex:i];
                GPGSignatureStatus	sigStatus;
                NSCalendarDate		*creationDate;
                NSString			*fingerPrint;
                
                if(!aKey)
                    break;
                sigStatus = [aContext statusOfSignatureAtIndex:i creationDate:&creationDate fingerprint:&fingerPrint];
                statusString = [statusString stringByAppendingFormat:@"\n%@ for %@ (Signed by %@ on %@)", [self stringFromSignatureStatus:sigStatus], fingerPrint, [aKey userID], creationDate];
            }
        }
        NSRunInformationalAlertPanel(@"Authentication result", statusString, nil, nil, nil);

        NSLog(@"Notations: %@", [aContext notationsAsXMLString]);
    NS_HANDLER
        NSLog(@"Exception userInfo: %@", [localException userInfo]);
        NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
    NS_ENDHANDLER

    [[NSNotificationCenter defaultCenter] removeObserver:self name:GPGProgressNotification object:aContext];
    [aContext release];
    [inputData release];
    [signatureData release];
}

- (IBAction) verify:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        [self authenticateFile:[openPanel filename] againstSignatureFile:nil];
    }
}

- (IBAction) verifyDetachedSignature:(id)sender
{
    NSOpenPanel	*openPanel = [NSOpenPanel openPanel];

    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setCanChooseDirectories:NO];
    [openPanel setCanChooseFiles:YES];
    [openPanel setAllowsMultipleSelection:NO];
    [openPanel setTreatsFilePackagesAsDirectories:YES];

    if([openPanel runModalForTypes:nil] == NSOKButton){
        NSString	*inputFilename = [[openPanel filename] copy];

        [openPanel setPrompt:@"Signature:"];

        if([openPanel runModalForTypes:nil] == NSOKButton){
            [self authenticateFile:inputFilename againstSignatureFile:[openPanel filename]];
        }
        [inputFilename release];
    }
}

- (IBAction) deleteKey:(id)sender
{
    GPGContext	*aContext = [[GPGContext alloc] init];

    NS_DURING
        NSEnumerator	*anEnum = [keyTableView selectedRowEnumerator];
        NSNumber		*aRow;

        while(aRow = [anEnum nextObject])
            [aContext deleteKey:[keys objectAtIndex:[aRow intValue]] evenIfSecretKey:[deleteSwitch state]];
    NS_HANDLER
        NSLog(@"Exception userInfo: %@", [localException userInfo]);
        NSRunAlertPanel(@"Error", @"%@", nil, nil, nil, [localException reason]);
    NS_ENDHANDLER
    [aContext release];
}

- (void) keyringChanged:(NSNotification *)notif
{
    [keyTableView noteNumberOfRowsChanged];
    [keyTableView reloadData];
}

@end
