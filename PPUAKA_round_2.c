/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_round_2.c
 */

/*
	Generate key materials and second hint and sign it.
 */

#include "PPUAKA_round_2.h"



void ppuaka_round_2(char* params_file,
					char* pseud_file,
					char* keypair_file,
					char* hint_1_file,
					char* msg_left_file,
					char* msg_right_file,
					char* sign_left_file,
					char* sign_right_file,
					char* key_material_file,
					char* msg_2_file,
					char* sign_2_file)
{

	//recover goods
	PPUAKA_params_t* params;
	PPUAKA_user_keypair_t* keypair;
	PPUAKA_user_pseud_t* pseud;
	PPUAKA_user_hint_t* hint_1;
	PPUAKA_user_message_t* msg_left;
	PPUAKA_user_message_t* msg_right;
	PPUAKA_user_signature_t* sign_left;
	PPUAKA_user_signature_t* sign_right;

	//output goods
	PPUAKA_user_key_material_t* key_material;
	PPUAKA_user_message_t* msg_2;
	PPUAKA_user_signature_t* sign_2;

	unsigned int index = 2;

	int verify_result;

	params 		= PPUAKA_params_unserialize (suck_file(params_file), 1);
	keypair 	= PPUAKA_keypair_unserialize (params, suck_file(keypair_file), 1);
	pseud		= PPUAKA_pseud_unserialize  (suck_file (pseud_file),1);
	hint_1 		= PPUAKA_hint_unserialize (params, suck_file(hint_1_file), 1);
	msg_left 	= PPUAKA_msg_unserialize (params, suck_file(msg_left_file), 1);
	msg_right 	= PPUAKA_msg_unserialize (params, suck_file(msg_right_file), 1);
	sign_left 	= PPUAKA_sign_unserialize (params, suck_file(sign_left_file), 1);
	sign_right	= PPUAKA_sign_unserialize (params, suck_file(sign_right_file), 1);

	verify_result = verify_r1(params, msg_left, msg_right, sign_left, sign_right);
//	element_printf("round_2-out-input: pubkey is %B\n", keypair->pub);
//	printf("round_2-out-input: left pid is %s\n", msg_left->pid);
//	printf("round_2-out-input: right pid is %s\n", msg_right->pid);
//	verify_result = verify_r1_test(params, msg_left, msg_right, sign_left, sign_right);
	printf("The result of 1st verification is %d\n", verify_result);

	if (verify_result)
	{
		printf("The signature verification is fail!\n");
	}
	else
	{
		key_material_gen (&key_material, &msg_2, params, pseud, msg_left, msg_right, hint_1, index);
		sign_gen(&sign_2, msg_2, params, keypair, hint_1, 2);

		spit_file(key_material_file, PPUAKA_key_material_serialize(key_material), 1);
		spit_file(msg_2_file, PPUAKA_msg_serialize(msg_2), 1);
		spit_file(sign_2_file, PPUAKA_sign_serialize(sign_2), 1);
	}


}

