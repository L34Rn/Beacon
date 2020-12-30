/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#include "common.h"
#include "crypt/hmac.h"
#include "crypt/aes.h"
#include "crypt/rsa.h"

/*-
 *
 * CryptInit
 *
 * Purpose:
 *
 * Init's the key / provider objects
 * for AES, RSA and HMAC-SHA-256
 *
-*/
DEFINESEC(B) BOOL CryptInit( PBEACON_INSTANCE Ins )
{
	if ( CryptRsaInit( Ins ) )
	{
		if ( CryptAesInit( Ins ) )
		{
			if ( CryptHmacInit( Ins ) )
			{
				return TRUE;
			};
			CryptAesFree( Ins );
		};
		CryptRsaFree( Ins );
	};
	return FALSE;
};

/*-
 *
 * CryptFree
 *
 * Purpose:
 *
 * Free's the key / provider objects
 * for AES, RSA, and HMAC-SHA-256
 *
-*/
DEFINESEC(B) VOID CryptFree( PBEACON_INSTANCE Ins )
{
	CryptHmacFree( Ins );
	CryptAesFree( Ins );
	CryptRsaFree( Ins );
};
