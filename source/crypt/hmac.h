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
 * CryptHmacInit
 *
 * Purpose:
 *
 * Creates the key object for HMAC
 *
-*/
DEFINESEC(B) BOOL CryptHmacInit( PBEACON_INSTANCE Ins );

/*-
 *
 * CryptHmacFree
 *
 * Purpose:
 *
 * Free's the associated keys for HMAC
 *
-*/
DEFINESEC(B) VOID CryptHmacFree( PBEACON_INSTANCE Ins );
