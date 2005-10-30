//
//  GPGSignatureNotation.h
//  MacGPGME
//
//  Created by davelopper at users.sourceforge.net on Sun Oct 9 2005.
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

#ifndef GPGSIGNATURENOTATION_H
#define GPGSIGNATURENOTATION_H

#include <MacGPGME/GPGObject.h>

#ifdef __cplusplus
extern "C" {
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


/*"
 * The flags of a GPGSignatureNotation is a combination of the following bit 
 * values:
 * _{GPGSignatureNotationHumanReadableMask  Specifies that the notation data is
 *                                          in human-readable form; not valid
 *                                          for policy URLs.}
 * _{GPGSignatureNotationCriticalMask       Specifies that the notation data is
 *                                          critical.}
"*/
typedef unsigned int GPGSignatureNotationFlags;

#define GPGSignatureNotationHumanReadableMask	1
#define GPGSignatureNotationCriticalMask		2



@interface GPGSignatureNotation : GPGObject /*"NSObject"*/
{

}

- (NSString *) name;
- (id) value;
- (GPGSignatureNotationFlags) flags;
- (BOOL) isHumanReadable;
- (BOOL) isCritical;

@end


#ifdef __cplusplus
}
#endif
#endif /* GPGSIGNATURENOTATION_H */
