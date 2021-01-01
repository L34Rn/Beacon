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
 * BeaconComputer
 *
 * Purpose:
 *
 * Returns a string containing the name
 * of the computer Beacon is running on
 *
-*/
DEFINESEC(B) PVOID BeaconComputer( PBEACON_INSTANCE Ins )
{
	PVOID Str = 0;
	ULONG Len = 0;

	if ( !Ins->api.GetComputerNameA( NULL, &Len ) )
	{
		if ((Str = Ins->api.LocalAlloc( LPTR, Len )))
		{
			if ( Ins->api.GetComputerNameA( Str, &Len ) )
			{
				return Str;
			};
			Ins->api.LocalFree( Str );
		};
	};
	return NULL;
};
