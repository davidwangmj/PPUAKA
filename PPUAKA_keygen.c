/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_keygen.c
 */

/*
	Generate session key.
 */

#include "PPUAKA_keygen.h"

void ppuaka_keygen(	char* params_file,
					char* keypair_file,
					char* key_material_file,
					char** msg_2_keygen_file,
					char** sign_2_keygen_file,
					char* session_key_file,
					int UserNum
					)
{

	int i;
	//recover goods

	PPUAKA_params_t* params;
	PPUAKA_user_keypair_t* keypair;
	PPUAKA_user_key_material_t* key_material;
	PPUAKA_user_message_t* msg_2_keygen [UserNum-1];
	PPUAKA_user_signature_t* sign_2_keygen [UserNum-1];

	//output goods

	PPUAKA_session_key_t* session_key;

	int verify_result;

	params 		= PPUAKA_params_unserialize (suck_file(params_file), 1);
	keypair 	= PPUAKA_keypair_unserialize (params, suck_file(keypair_file), 1);
	key_material= PPUAKA_key_material_unserialize (params, suck_file(key_material_file),1);

	for (i =1; i<= UserNum-1; i++)
	{
		msg_2_keygen [i-1] = PPUAKA_msg_unserialize (params, suck_file(msg_2_keygen_file[i-1]), 1);
		sign_2_keygen [i-1] = PPUAKA_sign_unserialize (params, suck_file(sign_2_keygen_file[i-1]), 1);
	}

	verify_result = verify_r2(params, msg_2_keygen, sign_2_keygen, UserNum);
	printf("The result of 2nd verification is %d\n", verify_result);

	if (verify_result)
		printf("The signature verification is fail!\n");
	else
	{
		keygen(&session_key, params, key_material, msg_2_keygen, UserNum);

	}

	spit_file(session_key_file, PPUAKA_session_key_serialize(session_key),1);




}
