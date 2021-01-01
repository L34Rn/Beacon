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
 * InfoGetComputer
 *
 * Purpose:
 *
 * Returns a pointer to a string 
 * with the full computer name
 * of the host.
 *
-*/
PVOID InfoGetComputer( PBEACON_INSTANCE Ins )
{
	PVOID Buf = 0;
	DWORD Len = 0;

	if ( !Ins->api.GetComputerNameA( NULL, &Len ) )
	{
		if ((Buf = Ins->api.LocalAlloc( LPTR, Len )))
		{
			if ( Ins->api.GetComputerName( Buf, &Len ) )
			{
				return Buf;
			};
			Ins->api.LocalFree( Buf );
		};
	};
	return NULL;
};
