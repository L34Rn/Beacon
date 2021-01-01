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
	BYTE	Key[16];
	BYTE	CharsetAnsi;
	BYTE	CharsetUnicode;
	ULONG	BeaconId;
	ULONG	ProcessId;
	USHORT	Port;
	BYTE	MetadataFlag;
	BYTE	MajorVersion;
	BYTE	MinorVersion;
	USHORT	Build;
	ULONG	Ptr;
	ULONG	GetModuleHandle;
	ULONG	GetProcAddress;
	ULONG	BeaconAddress;
	UCHAR	Buffer[0];
} BEACON_METADATA, *PBEACON_METADATA;
