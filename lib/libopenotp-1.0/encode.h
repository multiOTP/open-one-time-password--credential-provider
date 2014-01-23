/*
 RCDevs OpenOTP Development Library
 Copyright (c) 2010-2013 RCDevs SA, All rights reserved.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
  
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef __ENCODE_H
#define __ENCODE_H

#include <stdio.h>
#include <string.h>

int hex_encode(char *out, const char *in, int len);
int hex_decode(char *out, const char* in);

int base64_encode(char *dst, const char *src, int len);
int base64_decode(char *dst, const char *src);

#endif
