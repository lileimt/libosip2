#include <stdio.h>
#include <stdlib.h>
extern "C" {
#include <eXosip2/eXosip.h>
#include <osip2/osip_mt.h>
}

#ifdef WIN32
#include <WinSock2.h>
#endif

int main()
{
	eXosip_event_t *je = NULL;
	osip_message_t *ack = NULL;
	osip_message_t *invite = NULL;
	osip_message_t *answer = NULL;
	sdp_message_t *remote_sdp = NULL;

	const char *source_call = "sip:1000@127.0.0.1";
	const char *dest_call = "sip:1001@127.0.0.1:15060";

	struct eXosip_t *eXosip = eXosip_malloc();
	int i = eXosip_init(eXosip);
	if (i != OSIP_SUCCESS) {
		printf("Osip init error\n");
		return -1;
	}
	i = eXosip_listen_addr(eXosip, IPPROTO_UDP, NULL, 15061, AF_INET, 0);
	if (i != OSIP_SUCCESS) {
		eXosip_quit(eXosip);
		printf("Osip listen error\n");
		return -1;
	}

	int call_id, dialog_id;
	char tmp[4096]; 
	int pos = 0;
	for (;;) {
		je = eXosip_event_wait(eXosip, 0, 50);
		eXosip_lock(eXosip);
		eXosip_default_action(eXosip, je);
		eXosip_unlock(eXosip);
		if (je == NULL)continue;
		switch (je->type)
		{
		case EXOSIP_MESSAGE_NEW:
			if (MSG_IS_MESSAGE(je->request)) {
				osip_body_t *body;
				osip_message_get_body(je->request, 0, &body);
				eXosip_message_build_answer(eXosip, je->tid, 200, &answer);
				eXosip_message_send_answer(eXosip, je->tid, 200, answer);
			}
			break;
		case EXOSIP_CALL_INVITE:
			printf("Received a INVITE msg from %s:%s, UserName is %s, password is %s\n", je->request->req_uri->host,
				je->request->req_uri->port, je->request->req_uri->username, je->request->req_uri->password);
			//得到消息体,认为该消息就是SDP格式.  
			remote_sdp = eXosip_get_remote_sdp(eXosip, je->did);
			call_id = je->cid;
			dialog_id = je->did;

			eXosip_lock(eXosip);
			eXosip_call_send_answer(eXosip, je->tid, 180, NULL);
			i = eXosip_call_build_answer(eXosip, je->tid, 200, &answer);
			if (i != OSIP_SUCCESS)
			{
				printf("This request msg is invalid!Cann't response!\n");
				eXosip_call_send_answer(eXosip, je->tid, 400, NULL);
			}
			else
			{
				/*snprintf(tmp, 4096,
				"v=0\r\n"
				"o=anonymous 0 0 IN IP4 0.0.0.0\r\n"
				"t=1 10\r\n"
				"a=username:rainfish\r\n"
				"a=password:123\r\n");
				*/
				//设置回复的SDP消息体,下一步计划分析消息体  
				//没有分析消息体，直接回复原来的消息，这一块做的不好。  
				osip_message_set_body(answer, tmp, strlen(tmp));
				osip_message_set_content_type(answer, "application/sdp");

				eXosip_call_send_answer(eXosip, je->tid, 200, answer);
				printf("send 200 over!\n");
			}
			eXosip_unlock(eXosip);

			//显示出在sdp消息体中的attribute 的内容,里面计划存放我们的信息  
			printf("the INFO is :\n");
			while (!osip_list_eol(&(remote_sdp->a_attributes), pos))
			{
				sdp_attribute_t *at;
				at = (sdp_attribute_t *)osip_list_get(&remote_sdp->a_attributes, pos);
				printf("%s : %s\n", at->a_att_field, at->a_att_value);//这里解释了为什么在SDP消息体中属性a里面存放必须是两列  
				pos++;
			}
			break;
		case EXOSIP_CALL_ACK:
			break;
		case EXOSIP_CALL_CLOSED:
			printf("the remote hold the session!\n");
			// eXosip_call_build_ack(dialog_id, &ack);  
			//eXosip_call_send_ack(dialog_id, ack);   
			i = eXosip_call_build_answer(eXosip, je->tid, 200, &answer);
			if (i != OSIP_SUCCESS)
			{
				printf("This request msg is invalid!Cann't response!\n");
				eXosip_call_send_answer(eXosip, je->tid, 400, NULL);


			}
			else
			{
				eXosip_call_send_answer(eXosip, je->tid, 200, answer);
				printf("bye send 200 over!\n");
			}
			break;
		case EXOSIP_CALL_MESSAGE_NEW://至于该类型和EXOSIP_MESSAGE_NEW的区别，源代码这么解释的  
		/*
		// request related events within calls (except INVITE)
		EXOSIP_CALL_MESSAGE_NEW,          < announce new incoming request.
		// response received for request outside calls
		EXOSIP_MESSAGE_NEW,          < announce new incoming request.
		我也不是很明白，理解是：EXOSIP_CALL_MESSAGE_NEW是一个呼叫中的新的消息到来，比如ring trying都算，所以在接受到后必须判断
		该消息类型，EXOSIP_MESSAGE_NEW而是表示不是呼叫内的消息到来。
		该解释有不妥地方，仅供参考。
		*/
			printf(" EXOSIP_CALL_MESSAGE_NEW\n");
			if (MSG_IS_INFO(je->request)) //如果传输的是INFO方法  
			{
				eXosip_lock(eXosip);
				i = eXosip_call_build_answer(eXosip, je->tid, 200, &answer);
				if (i == 0)
				{
					eXosip_call_send_answer(eXosip, je->tid, 200, answer);
				}
				eXosip_unlock(eXosip);
				{
					osip_body_t *body;
					osip_message_get_body(je->request, 0, &body);
					printf("the body is %s\n", body->body);
				}
			}
			break;
		default:
			break;
		}
	}

	return 0;
}