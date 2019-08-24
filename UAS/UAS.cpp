#include <stdio.h>
#include <stdlib.h>
extern "C" {
#include <eXosip2/eXosip.h>
#include <osip2/osip_mt.h>
}

int main()
{
	eXosip_event_t *je = NULL;
	osip_message_t *ack = NULL;
	osip_message_t *invite = NULL;
	osip_message_t *answer = NULL;
	sdp_message_t *remote_sdp = NULL;

	const char *source_call = "sip:1000@127.0.0.1";
	const char *dest_call = "sip:1001@127.0.0.1:5060";

	struct eXosip_t *eXosip = eXosip_malloc();
	int i = eXosip_init(eXosip);

	return 0;
}