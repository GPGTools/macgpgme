//
//  GPGDefines.h
//  GPGME
//
//  Created by stephane@sente.ch on Tue Aug 14 2001.
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
//  <stephane@sente.ch>.
//

#if defined(__WIN32__)
    #undef GPG_EXPORT
    #if defined(BUILDINGGPG)
    #define GPG_EXPORT __declspec(dllexport) extern
    #else
    #define GPG_EXPORT __declspec(dllimport) extern
    #endif
    #if !defined(GPG_IMPORT)
    #define GPG_IMPORT __declspec(dllimport) extern
    #endif
#endif

#if !defined(GPG_EXPORT)
    #define GPG_EXPORT extern
#endif

#if !defined(GPG_IMPORT)
    #define GPG_IMPORT extern
#endif

#if !defined(GPG_STATIC_INLINE)
#define GPG_STATIC_INLINE static __inline__
#endif

#if !defined(GPG_EXTERN_INLINE)
#define GPG_EXTERN_INLINE extern __inline__
#endif

