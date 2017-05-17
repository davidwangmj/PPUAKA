/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_register.c
 */

/*
 *	Generate key hint and sign it.
 */

#include "PPUAKA_round_1.h"




void ppuaka_round_1(char* params_file,
					char* pseud_file,
					char* keypair_file,
					char* sid_file,
					char* hint_1_file,
					char* msg_1_file,
					char* sign_1_file)
{

	PPUAKA_params_t* params;
	PPUAKA_user_pseud_t* user_pseud;
	PPUAKA_user_keypair_t* keypair;

	PPUAKA_session_id_t* sessionid;
	PPUAKA_user_hint_t* hint_1;
	PPUAKA_user_message_t* msg_1;
	PPUAKA_user_signature_t* sign_1;

	unsigned int index = 1;	//index numnber in message
	//int i = 0;

	params = PPUAKA_params_unserialize (suck_file(params_file), 1);
	//test
//	GByteArray * Gbyte_temp = suck_file(pseud_file);
//	printf("Gbyte length %d\n", Gbyte_temp->len);
//	for(i = 0; i < Gbyte_temp->len; i ++)
//	{
//		printf("%d\t", Gbyte_temp->data[i]);
//		if(i%10 == 9)
//			printf("\n");
//	}
//	printf("\n");
//
//	for(i = 0; i < Gbyte_temp->len; i ++)
//	{
//		printf("%c\t", Gbyte_temp->data[i]);
//		if(i%10 == 9)
//			printf("\n");
//	}


	//user_pseud = PPUAKA_pseud_unserialize (Gbyte_temp, 1);
	//test end
	user_pseud = PPUAKA_pseud_unserialize (suck_file(pseud_file), 1);


	keypair = PPUAKA_keypair_unserialize (params, suck_file(keypair_file), 1);

	sessionid = (PPUAKA_session_id_t*)malloc(sizeof(PPUAKA_session_id_t));
	sessionid->sid = malloc (sizeof(char)*10);

	sessionid->sid = "002";
//	printf("Pleas input the session ID:\n");
//	scanf("%s", sessionid->sid);
//	printf("Session ID is %s.\n", sessionid->sid);

	//test start
//	printf("*****************************************************************************\n");
//	printf("round_1--input: pairing desc is %s\n", params->pairing_desc);
//	element_printf("round_1--input: g is %B\n", params->g);
//	element_printf("round_1--input: h is %B\n", params->h);
//	element_printf("round_1--input: g_hat_alpha is %B\n", params->g_hat_alpha);
//	printf("round_1--input:Session ID is %s.\n", sessionid->sid);
	printf("round1: main: pesud id is %s\n", user_pseud->pid);
	printf("round_1--input: timestamp  is %s.\n", user_pseud->timestamp);
	//test end

	user_hint_gen (&hint_1, &msg_1, params, user_pseud, sessionid, index);
	sign_gen (&sign_1, msg_1, params, keypair, hint_1, 1);

	//test start
//	printf("round-1--output: Session ID is %s.\n", msg_1->sid);
//	printf("round-1--output: pid is %s\n", msg_1->pid);
//	element_printf("round_1--output:beta is %B\n", hint_1->beta);
//	element_printf("round_1--output:hint_1 is %B\n", hint_1->hint_first);
//	element_printf("round_1--output:hint_1 is %B\n", msg_1->hint_first);
//	element_printf("round_1--output:sig-u is %B\n", sign_1->u);
//	element_printf("round_1--output:sig-h is %B\n", sign_1->h);
//	element_printf("round_1--output:sig-v is %B\n", sign_1->v);
//	printf("*****************************************************************************\n");

	//test end

	spit_file(sid_file, PPUAKA_sessionid_serialize(sessionid), 1);
	spit_file(hint_1_file, PPUAKA_hint_serialize(hint_1), 1);
	spit_file(msg_1_file, PPUAKA_msg_serialize(msg_1), 1);
	spit_file(sign_1_file, PPUAKA_sign_serialize(sign_1), 1);

}




