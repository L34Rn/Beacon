/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

typedef struct __attribute__((packed, scalar_storage_order("big-endian")))
{
	ULONG	Magic;
	ULONG	Length;
	UCHAR	Buffer[0];
} BEACON_METADATA_HDR, *PBEACON_METADATA_HDR;
