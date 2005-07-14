//
//  GPGRemoteKey.m
//  MacGPGME
//
//  Created by Robert Goldsmith (r.s.goldsmith@far-blue.co.uk) on Sat July 9 2005.
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

#include <MacGPGME/GPGRemoteKey.h>
#include <MacGPGME/GPGRemoteUserID.h>
#include <MacGPGME/GPGPrettyInfo.h>
#include <MacGPGME/GPGInternals.h>
#include <Foundation/Foundation.h>
#include <gpgme.h>


@implementation GPGRemoteKey

/*"
* Rather than returning actual keys from a remote key match, a key server will
 * reply with token representations of the keys, in the form of #GPGRemoteKey
 * instances. #GPGRemoteKey instances are NOT real keys, and cannot be treated as
 * such. However, they can be compared against actual keys by checking the %shortKeyID
 * of two keys.
 * 
 * #GPGRemoteKey instances are returned by
 * #{-[GPGContext asyncSearchForKeysMatchingPatterns:serverOptions:]}
 *
 * #GPGRemoteKey instances can be passed (in any combination with normal keys) to
 * #{[GPGContext asyncDownloadKeys:serverOptions]}
 *
 * #GPGRemoteKey instances are immutable and should never be created manually.   
 "*/


- (NSDictionary *) dictionaryRepresentation
  /*"
 * Returns a dictionary that looks something like this:
 *
 * !{{
	 algo = 17; 
	 created = 2003-05-29 00:33:31 +0100; 
	 expired = 0; 
	 keyid = 2E92F423; 
	 len = 1024; 
	 revoked = 0; 
	 userids = (
		  "Robert Scott Goldsmith <R.S.Goldsmith@cs.bham.ac.uk>", 
		  "Robert Scott Goldsmith <R.S.Goldsmith@Far-Blue.co.uk>"
	  ); 
   }}
 "*/
{
  NSMutableDictionary	*key_dict = [NSMutableDictionary dictionary];
  
  [key_dict setObject: [NSNumber numberWithBool:[self isKeyRevoked]] forKey:@"revoked"];
  [key_dict setObject: [NSNumber numberWithBool:[self hasKeyExpired]] forKey:@"expired"];
  [key_dict setObject: [self keyID] forKey: @"keyid"];
  [key_dict setObject: [NSNumber numberWithInt:[self algorithm]] forKey:@"algo"];
  [key_dict setObject: [NSNumber numberWithInt:[self length]] forKey:@"len"];
  if ([self creationDate])
	[key_dict setObject: [self creationDate] forKey:@"created"];
  if ([self expirationDate])
	[key_dict setObject: [self expirationDate] forKey:@"expire"];  
  if([self userIDs] != nil)
  {
	NSMutableArray *uidArray=[NSMutableArray arrayWithCapacity:[[self userIDs] count]];
	NSEnumerator *uidEnumerator=[[self userIDs] objectEnumerator];
	id currentUID;
	while(currentUID=[uidEnumerator nextObject])
	  [uidArray addObject:[currentUID userID]];
	[key_dict setObject:uidArray forKey:@"userids"];
  }
  return key_dict;
}

- (NSString *) keyID
  /*"
  * Returns the key id in hexidecimal digits.
  "*/
{
  switch(_version){
	case 0:
	  return [[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:0];
	case 1:
	  return [[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:1];
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return nil; // Never reached
  }
}

- (GPGPublicKeyAlgorithm) algorithm
/*"
 * Returns %{key algorithm}. The algorithm is the crypto algorithm for 
 * which the %key (once downloaded) can be used. The value corresponds to the
 * #GPGPublicKeyAlgorithm enum values.
"*/
{
  NSString	*aString;
  
  switch(_version){
	case 0:
            // We need to make an inverse mapping between name (sometimes given)
            // and the numerical value
	  aString = [self algorithmDescription];
	  return [self algorithmFromName:aString];
	case 1:
	  aString = [[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:2];
	  if([aString length] > 0)
		return [aString intValue];
	  else
		return -1;
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return -1; // Never reached
  }
}

- (NSString *) algorithmDescription
/*"
 * Convenience method. Returns a non-localized description of the algorithm.
"*/

{
  switch(_version){
	case 0:
	  return [self unescapedString:[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:6]]; // Not always available, not localized
	case 1:
	  return GPGPublicKeyAlgorithmDescription([self algorithm]);
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return nil; // Never reached
  }
}

- (unsigned int) length
/*"
 * Returns %{key} length, in bits.
"*/
{
  switch(_version){
	case 0:
            // Might return 0, because info was not available
	  return (unsigned)[[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:7] intValue];
	case 1:
	  return (unsigned)[[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:3] intValue];
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return 0; // Never reached
  }
}

- (NSCalendarDate *) creationDate
/*"
 * Returns %{key} creation date. Returns nil when not available or invalid.
"*/
{
  int	aValue;
  
  switch(_version){
	case 0:
	  aValue = [[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:3] intValue]; break;
	case 1:
	  aValue = [[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:4] intValue]; break;
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return nil; // Never reached
  }
  return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
}


- (NSCalendarDate *) expirationDate
/*"
 * Returns %{key} expiration date. Returns nil when there is none or is not available or is invalid.
"*/
{
  NSString	*aString;
  
  switch(_version){
	case 0:
	  aString = [[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:4]; break;
	case 1:
	  aString = [[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:5]; break;
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return nil; // Never reached
  }
  if([aString length] > 0){
	int	aValue = [aString intValue];
	
	if(aValue != 0)
	  return [NSCalendarDate dateWithTimeIntervalSince1970:aValue];
	else
	  return nil;
  }
  else
	return nil; // Information not available
}


- (NSArray *) userIDs
/*"
 * Returns the %{user IDs}, as #GPGRemoteUserID instances.
"*/
{
  if(_userIDs == nil){
	int		i = 0;
	int		max = [_colonFormatStrings count];
	NSZone	*aZone = [self zone];
	
	switch(_version){
	  case 0:
		i = 0; break;
	  case 1:
		i = 1; break;
	  default:
		[NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
		return nil; // Never reached
	}
	_userIDs = [[NSMutableArray allocWithZone:aZone] initWithCapacity:max];
	for(; i < max; i++){
	  GPGRemoteUserID	*aUserID = [[GPGRemoteUserID allocWithZone:aZone] initWithKey:self index:i];
	  
	  [(NSMutableArray *)_userIDs addObject:aUserID];
	  [aUserID release];
	}
  }
  
  return _userIDs;
}


- (BOOL) isKeyRevoked
/*"
 * Returns whether key is revoked.
"*/
{
  switch(_version){
	case 0:
	  return !![[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:2] intValue];
	case 1:
	  return [[[[_colonFormatStrings objectAtIndex:0] componentsSeparatedByString:@":"] objectAtIndex:6] rangeOfString:@"r"].location != NSNotFound;
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
	  return 0; // Never reached
  }
}

- (BOOL) hasKeyExpired
/*"
 * Returns whether key is expired.
"*/
{
  NSCalendarDate	*expirationDate = [self expirationDate];
  
  if(expirationDate != nil && [expirationDate compare:[NSCalendarDate calendarDate]] <= 0)
	return YES;
  
  return NO; // Information not available
}



- (unsigned) hash
  /*"
  * Returns hash value based on %keyId.
   "*/
{
  if([self keyID] != nil)
	return [[self keyID] hash];
  return [super hash];
}

- (BOOL) isEqual:(id)anObject
/*"
* Returns YES if both the receiver and anObject have the same %keyID and of the same
* class.
"*/
{
  if(anObject != nil && [anObject isMemberOfClass:[self class]])
	return [[self keyID] isEqualToString:[anObject keyID]];
  
  return NO;
}


- (GPGRemoteUserID *) primaryUserID
{
    // It MIGHT happen that a key has NO userID!
  NSArray	*userIDs = [self userIDs];
  
  if([userIDs lastObject] != nil)
	return [userIDs objectAtIndex:0];
  else
	return nil;
}

- (NSString *) shortKeyID
  /*"
  * Convenience method. Returns %{short (32 bit) key ID}.
   "*/
{  
  return [[self keyID] substringFromIndex:[[self keyID] length] - 8];
}


- (NSString *) userID
  /*"
  * Convenience method. Returns the %{primary user ID}.
   "*/
{
      // It MIGHT happen that a key has NO userID!
  NSArray	*userIDs = [self userIDs];
  
  if([userIDs lastObject] != nil)
	return [[userIDs objectAtIndex:0] userID];
  else
	return nil;
}

@end


@implementation GPGRemoteKey(GPGInternals)

- (id) initWithColonOutputStrings:(NSArray *)strings version:(int)version
{
  if(self = [self initWithInternalRepresentation:NULL]){
	_colonFormatStrings = [strings copyWithZone:[self zone]];
	_version = version;
  }
  
  return self;
}

- (void) dealloc
{
  [_colonFormatStrings release];
  
  [super dealloc];
}

- (NSArray *) colonFormatStrings
{
  return _colonFormatStrings;
}

- (int) colonFormatStringsVersion
{
  return _version;
}

- (NSString *) unescapedString:(NSString *)string
{
    // Version 0: replaces \xXX sequences with ASCII character matching hexcode XX
    // Version 1: replaces %XX sequences with ASCII character matching hexcode XX
  NSMutableString	*newString = [NSMutableString stringWithString:string];
  NSRange			aRange;
  NSString		*escapeCode = nil;
  unsigned		escapeCodeLength = 0;
  BOOL			neededToUnescape = NO;
  
  switch(_version){
	case 0:
	  escapeCode = @"\\x";
	  escapeCodeLength = 2;
	  break;
	case 1:
	  escapeCode = @"%";
	  escapeCodeLength = 1;
	  break;
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", _version];
  }
  
  while((aRange = [newString rangeOfString:escapeCode]).length > 0){
	NSString	*hexCodeString = [newString substringWithRange:NSMakeRange(aRange.location + escapeCodeLength, 2)];
	unichar		hiChar = [hexCodeString characterAtIndex:0];
	unichar		loChar = [hexCodeString characterAtIndex:1];
	
	if(hiChar >= 'a')
	  hiChar = hiChar - 'a' + 10;
	else if(hiChar >= 'A')
	  hiChar = hiChar - 'A' + 10;
	else
	  hiChar -= '0';
	if(loChar >= 'a')
	  loChar = loChar - 'a' + 10;
	else if(loChar >= 'A')
	  loChar = loChar - 'A' + 10;
	else
	  loChar -= '0';
	hiChar = hiChar * 16 + loChar;
	
	[newString replaceCharactersInRange:NSMakeRange(aRange.location, escapeCodeLength + 2) withString:[NSString stringWithCharacters:&hiChar length:1]];
	neededToUnescape = YES;
  }
  
  if(neededToUnescape && _version == 1){
		// New in 1.4? Accents are passed correctly, always escaped. This means
		// that we need _now_ to transform to UTF8: what we got was not UTF8!
		// Does happen with my key from wwwkeys.us.pgp.net, but not from ldap://keyserver.pgp.com
	NSData		*rawData = [newString dataUsingEncoding:NSISOLatin1StringEncoding];
	NSString	*decodedString = [[NSString alloc] initWithData:rawData encoding:NSUTF8StringEncoding];
	
	if(decodedString != nil){
	  [newString setString:decodedString];
	  [decodedString release];
	}
  }
  
  return newString;
}


- (GPGPublicKeyAlgorithm)algorithmFromName:(NSString *)name
{
  static NSDictionary	*algoForNameDict = nil;
  NSNumber			*aNumber;
  
  if(algoForNameDict == nil)
#warning CHECK!
	algoForNameDict = [[NSDictionary alloc] initWithObjectsAndKeys:
	  [NSNumber numberWithInt:GPG_RSAAlgorithm], @"RSA", // OK
	  [NSNumber numberWithInt:GPG_RSAEncryptOnlyAlgorithm], @"RSA-S",
	  [NSNumber numberWithInt:GPG_RSASignOnlyAlgorithm], @"RSA-E",
	  [NSNumber numberWithInt:GPG_ElgamalEncryptOnlyAlgorithm], @"ELG-E", // OK
	  [NSNumber numberWithInt:GPG_DSAAlgorithm], @"DSA", // OK
	  [NSNumber numberWithInt:GPG_DSAAlgorithm], @"DSS/DH", // OK; there are 2 names, but it's very complicated; google ("DSS/DH" DSA) to learn more
	  [NSNumber numberWithInt:GPG_EllipticCurveAlgorithm], @"Elliptic",
	  [NSNumber numberWithInt:GPG_ECDSAAlgorithm], @"ECDSA",
	  [NSNumber numberWithInt:GPG_ElgamalAlgorithm], @"ELG",
	  [NSNumber numberWithInt:GPG_DiffieHellmanAlgorithm], @"DH", nil];
  
  aNumber = [algoForNameDict objectForKey:name];
  if(aNumber == nil)
	return -1;
  else
	return [aNumber intValue];
}
@end

