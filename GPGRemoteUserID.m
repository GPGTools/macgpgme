//
//  GPGRemoteUserID.m
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


@implementation GPGRemoteUserID
/*"
* A remote user ID is a component of a #GPGRemoteKey object.
 * One key can have many user IDs. 
 *
 * A %{remote user ID} represents an identity associated with a remote key. This identity is
 * generally composed of a name and an email adress, and can have a comment
 * associated.
 *
 * #GPGRemoteUserID instances are immutable and should never be created manually.   
 "*/


- (NSString *) userID
/*"
 * Returns the %{user ID} as "Name (Comment) <Email>".
"*/
{
  switch([(GPGRemoteKey *)_key colonFormatStringsVersion]){
	case 0:
	  return [(GPGRemoteKey *)_key unescapedString:[[[[(GPGRemoteKey *)_key colonFormatStrings] objectAtIndex:_index] componentsSeparatedByString:@":"] objectAtIndex:1]];
	case 1:
	  return [(GPGRemoteKey *)_key unescapedString:[[[[(GPGRemoteKey *)_key colonFormatStrings] objectAtIndex:_index] componentsSeparatedByString:@":"] objectAtIndex:1]];
	default:
	  [NSException raise:NSGenericException format:@"### Unknown version (%d)", [(GPGRemoteKey *)_key colonFormatStringsVersion]];
	  return nil; // Never reached
  }
}

- (GPGRemoteKey *) key
  /*"
  * Returns the key owning that userID.
   "*/
{
  return _key;
}

@end


@implementation GPGRemoteUserID(GPGInternals)

- (id) initWithKey:(GPGRemoteKey *)key index:(int)index
{
  if(self = [self init]){
	((GPGRemoteUserID *)self)->_key = key; // Not retained
	((GPGRemoteUserID *)self)->_index = index;
  }
  
  return self;
}
@end
