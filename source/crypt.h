/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

typedef struct
{
	BLOBHEADER Hdr;
	DWORD      Len;
	UCHAR      Buf[ 32 ];
} CRYPT_KEY_BUFFER, *PCRYPT_KEY_BUFFER;
