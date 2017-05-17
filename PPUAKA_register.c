/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_register.c
 */

/*
 *	Generate user pseudonym and public/private key pair for this pseudonym.
 */

#include "PPUAKA_register.h"

void
ppuaka_register(int user_num)
{

	//input
	PPUAKA_params_t* params;
	PPUAKA_msk_t* msk;

	//output
	PPUAKA_user_realid_t* user_realid;
	PPUAKA_user_pseud_t* user_pseud;
	PPUAKA_user_keypair_t* user_keypair;

	// for multi user register
	int i;
	int user_id_length = 10;
	char* params_file = "params_key";
	char* msk_file = "msk_key";
	params = PPUAKA_params_unserialize (suck_file(params_file), 1);
	msk = PPUAKA_msk_unserialize (params, suck_file(msk_file), 1);

	//test start
//	printf("*****************************************************************************\n");
//	printf("register--input: pairing desc is %s\n", params->pairing_desc);
//	element_printf("register--input: g is %B\n", params->g);
//	element_printf("register--input: h is %B\n", params->h);
//	element_printf("register--input: g_hat_alpha is %B\n", params->g_hat_alpha);
//	element_printf("register--input: msk key is %B\n", msk->alpha);
//	printf("*****************************************************************************\n");

	//test end

	user_realid = (PPUAKA_user_realid_t*)malloc(sizeof(PPUAKA_user_realid_t));
	user_realid->rid = (char*)malloc (sizeof(char)*20);

	user_pseud = (PPUAKA_user_pseud_t*)malloc(sizeof(PPUAKA_user_pseud_t));
	user_pseud->pid = (char*)malloc(SHA_DIGEST_LENGTH+2);
	user_pseud->timestamp = (char*)malloc(sizeof(char)*100);

	//get user id from scanf 1 by 1
//	printf("Pleas input the real ID:\n");
//	scanf("%s", user_realid->rid);
//	printf("recover: real id is %s.\n", user_realid->rid);

	//get user id from random generation string
//	printf("Please set the number of system user:\n");
//	scanf("%d", &user_num);
//	printf("The number of system user initialized is %d.\n", user_num);
//
//	printf("Please set the length of user real id:\n");
//	scanf("%d", &user_id_length);
//	printf("The length of user real id is %d.\n", user_id_length);

	//for (i = 1; i<=user_num; i++)
	for (i = 1; i<=user_num; i++)
	{
		//i = i%3;

		char* realid_u_file = 0;
		char* pseud_u_file = 0;
		char* keypair_u_file = 0;

		realid_u_file = malloc (sizeof("realid_")+user_id_length);
		pseud_u_file = malloc (sizeof("pseud_")+user_id_length);
		keypair_u_file = malloc (sizeof("keypair_")+user_id_length);
		strcpy(realid_u_file, "realid_");
		strcpy(pseud_u_file, "pseud_");
		strcpy(keypair_u_file, "keypair_");

		sprintf(user_realid->rid, "%d", i);



		//user_realid->rid = genRandomString (user_id_length+1);
		//test
		printf("real id is %s\n", user_realid->rid);



		user_register(&user_keypair, &user_pseud, params, msk, user_realid);

//		element_printf("register-out-output: pubkey is %B\n", user_keypair->pub);
//		printf("register: main: output: pid is %s\n", user_pseud->pid);
//		fflush(stdout);
//		printf("register: main: output: ts is %s\n", user_pseud->timestamp);

		//set the name of output file
		keypair_u_file = strcat(keypair_u_file, user_realid->rid);
		realid_u_file = strcat(realid_u_file, user_realid->rid);
		pseud_u_file = strcat(pseud_u_file, user_realid->rid);

		spit_file(keypair_u_file, PPUAKA_keypair_serialize(user_keypair), 1);
		spit_file(realid_u_file, PPUAKA_realid_serialize(user_realid), 1);
		spit_file(pseud_u_file, PPUAKA_pseud_serialize(user_pseud), 1);

		free(keypair_u_file);
		free(realid_u_file);
		free(pseud_u_file);
	}

	//test start
//	printf("recover: real id is %s.\n", user_realid->rid);
//	element_printf("out_function:pub_u is %B\n", user_keypair->pub);
//	element_printf("out_function:prv_u is %B\n", user_keypair->prv);
	//test end
}


