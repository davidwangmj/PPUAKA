/* 
 * Implementation of WANG-YAN's PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * main.c
 */

#include "PPUAKA_setup.h"
#include "PPUAKA_register.h"
#include "PPUAKA_round_1.h"
#include "PPUAKA_round_2.h"
#include "PPUAKA_keygen.h"

int main() {

	int i,j;
  
	int user_num = 20;    //The number of users in group can be changed.
	//int user_id_length = 10;

	char* params_file = "params_key";

	//define prefix
	char* pseud_file_prefix = "pseud_";
	char* keypair_file_prefix = "keypair_";
	char* sid_file_prefix = "sid_file_";

	char* hint_1_file_prefix = "hint_r1_";
	char* msg_1_file_prefix = "msg_r1_";
	char* sign_1_file_prefix = "sign_r1_";

	char* msg_left_file_prefix = "msg_r1_";
	char* msg_right_file_prefix = "msg_r1_";
	char* sign_left_file_prefix = "sign_r1_";
	char* sign_right_file_prefix = "sign_r1_";
	char* key_material_file_prefix = "key_material_";
	char* msg_2_file_prefix = "msg_r2_";
	char* sign_2_file_prefix =  "sign_r2_";

	char* session_key_file_prefix = "session_key_";


	//

	char* pseud_file = (char *) malloc(sizeof(char) * 16);
	char* keypair_file = (char *) malloc(sizeof(char) * 16);
	char* sid_file = (char *) malloc(sizeof(char) * 16);

	char* hint_1_file = (char *) malloc(sizeof(char) * 16);
	char* msg_1_file = (char *) malloc(sizeof(char) * 16);
	char* sign_1_file = (char *) malloc(sizeof(char) * 16);

	char* msg_left_file = (char *) malloc(sizeof(char) * 16);
	char* msg_right_file = (char *) malloc(sizeof(char) * 16);
	char* sign_left_file = (char *) malloc(sizeof(char) * 16);
	char* sign_right_file = (char *) malloc(sizeof(char) * 16);
	char* key_material_file = (char *) malloc(sizeof(char) * 16);

	char* msg_2_file = (char *) malloc(sizeof(char) * 16);
	char* sign_2_file = (char *) malloc(sizeof(char) * 16);
	char* session_key_file = (char *) malloc (sizeof(char) *16);

	// 存放sign_2和msg_2的数组
	char* msg_2_keygen_file [user_num-1];
	char* sign_2_keygen_file [user_num-1];

	//setup
	ppukak_setup();

	//user register
	ppuaka_register(user_num);


	//round 1
	for (i = 1; i <= user_num; i++)
	//for (i = 12; i<=13; i++)
	{

		memset(pseud_file, 0, 16);
		sprintf(pseud_file, "%s%d", pseud_file_prefix, i);
		memset(keypair_file, 0, 16);
		sprintf(keypair_file, "%s%d", keypair_file_prefix, i);
		memset(sid_file, 0, 16);
		sprintf(sid_file, "%s%d", sid_file_prefix, i);
		memset(hint_1_file, 0, 16);
		sprintf(hint_1_file, "%s%d", hint_1_file_prefix, i);
		memset(msg_1_file, 0, 16);
		sprintf(msg_1_file, "%s%d", msg_1_file_prefix, i);
		memset(sign_1_file, 0, 16);
		sprintf(sign_1_file, "%s%d", sign_1_file_prefix, i);

		printf("sign: %d------------------------------------------\n", i);
		ppuaka_round_1(params_file, pseud_file, keypair_file, sid_file, hint_1_file, msg_1_file, sign_1_file);

	}
	//round 1 end

	//round 2
	for (i = 1; i<=user_num; i++)
	//for (i = 12; i<=13; i++)
	{
		memset(pseud_file, 0, 16);
		sprintf(pseud_file, "%s%d", pseud_file_prefix, i);
		memset(keypair_file, 0, 16);
		sprintf(keypair_file, "%s%d", keypair_file_prefix, i);
		memset(hint_1_file, 0, 16);
		sprintf(hint_1_file, "%s%d", hint_1_file_prefix, i);

		memset(msg_left_file, 0, 16);
		memset(sign_left_file, 0, 16);

		if ((i-1) == 0)
		{
			sprintf(msg_left_file, "%s%d", msg_left_file_prefix, user_num);
			sprintf(sign_left_file, "%s%d", sign_left_file_prefix, user_num);
		}
		else
		{
			sprintf(msg_left_file, "%s%d", msg_left_file_prefix, i-1);
			sprintf(sign_left_file, "%s%d", sign_left_file_prefix, i-1);
		}

		memset(msg_right_file, 0, 16);
		memset(sign_right_file, 0, 16);

		if(i == user_num)
		{
			sprintf(msg_right_file, "%s%d", msg_right_file_prefix, 1);
			sprintf(sign_right_file, "%s%d", sign_right_file_prefix, 1);
		}
		else
		{
			sprintf(msg_right_file, "%s%d", msg_right_file_prefix, i+1);
			sprintf(sign_right_file, "%s%d", sign_right_file_prefix, i+1);
		}


		memset(key_material_file, 0, 16);
		sprintf(key_material_file, "%s%d", key_material_file_prefix, i);
		memset(msg_2_file, 0, 16);
		sprintf(msg_2_file, "%s%d", msg_2_file_prefix, i);
		memset(sign_2_file, 0, 16);
		sprintf(sign_2_file, "%s%d", sign_2_file_prefix, i);

		printf("verify: %d------------------------------------------\n", i);
		ppuaka_round_2(params_file, pseud_file, keypair_file, hint_1_file, msg_left_file, msg_right_file, sign_left_file, sign_right_file, key_material_file, msg_2_file, sign_2_file );

	}
	// round 2 end

	//session key gen
	//input:
	//Ui keypair, key material
	//Uj msg_2, sign_2


	//test i = 1;
		i = 1;
		memset(keypair_file, 0, 16);
		sprintf(keypair_file, "%s%d", keypair_file_prefix, i);
		memset(key_material_file, 0, 16);
		sprintf(key_material_file, "%s%d", key_material_file_prefix, i);

		for (j = i+1; j <= user_num; j++)
		{
			msg_2_keygen_file[j-2] = (char *) malloc(sizeof(char) * 16);
			sign_2_keygen_file[j-2] = (char *) malloc(sizeof(char) * 16);
			memset(msg_2_keygen_file[j-2], 0, 16);
			memset(sign_2_keygen_file[j-2],0, 16);
			sprintf(msg_2_keygen_file[j-2], "%s%d", msg_2_file_prefix, j);
			sprintf(sign_2_keygen_file[j-2], "%s%d", sign_2_file_prefix, j);

		}

		memset(session_key_file, 0, 16);
		sprintf(session_key_file, "%s%d", session_key_file_prefix, i);

		ppuaka_keygen(params_file, keypair_file, key_material_file, msg_2_keygen_file, sign_2_keygen_file, session_key_file, user_num);

	//}

	//session key gen end


	return 0;
}
