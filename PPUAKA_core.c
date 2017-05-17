/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA.c
 */


#include "PPUAKA_core.h"


/* Free Functions

void Free_system_params(system_params_t params)
{
	if(!params)
	{	prinft("error:null pointer passed to Free_system_params.\n");
		return;
	};
	pbc_free(params->pairFileName);
	element_clear(params->g);
	element_clear(params->h);
	element_clear(params->g_hat_alpha);
	free(params);
	return;
}

void Free_system_msk (system_msk_t msk)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_system_msk.\n");
		return;
	};
	element_clear(msk->alpha);
	return;
}


void Free_user_realid (user_realid_t realid)
{
	if(!realid)
	{	prinft("error:null pointer passed to Free_user_realid.\n");
		return;
	};

	free(rid);
	return;
}

void Free_user_pseud (user_pseud_t pseud)
{
	if(!pseud)
	{	prinft("error:null pointer passed to Free_user_pseud.\n");
		return;
	};

	free(pid);

	return;
}

void Free_user_keypair (user_keypair_t keypair)
{
	if(!keypair)
	{	prinft("error:null pointer passed to Free_user_keypair.\n");
		return;
	};

	element_clear(keypair->pub_key);
	element_clear(keypair->prv_key);
	free(keypair);

	return;
}

void Free_user_hint (user_hint_t hint)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_hint.\n");
		return;
	};
	element_clear(hint->beta);
	element_clear(hint->hint);
	free(hint);

	return;
}

void Free_user_key_material (user_key_material_t material)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_key_material.\n");
		return;
	};
	element_clear(material->left_key);
	element_clear(material->right_key);
	element_clear(material->hint_plus);
	free(material);

	return;
}

void Free_user_signature (sign_t sign)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_signature.\n");
		return;
	};
	element_clear(sign->u);
	element_clear(sign->h);
	element_clear(sign->v);
	free(sign);

	return;
}

void Free_user_session_key (session_key_t sk)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_session_key.\n");
		return;
	};
	element_clear(sk->k);
	free(sk);

	return;
}
*/


/* Hash Functions H1, H2, H3*/

void element_from_string_1( element_t h, char* s )
{
	unsigned char* r;

	r = (unsigned char*)malloc(SHA_DIGEST_LENGTH);
	memset(r, 0, SHA_DIGEST_LENGTH);

	//printf("SHA_DIGEST_LENGT is %d", SHA_DIGEST_LENGTH);

	//printf("string1--input------test: s is %s\n", s);

	SHA1((unsigned char*) s, strlen(s), r);

	//printf("string1--output------test: s is %s\n", s);
	//printf("string1--output------test: s is %s\n", (char*)s);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

//void element_from_string_3( element_t h, element_t t )
//{
//	int length;
//	unsigned char* r1;
//	unsigned char* r2;
//
//	length = element_length_in_bytes (t);
//	r1 = malloc(length);
//	element_to_bytes(r1, t);
//
//	r2 = malloc(SHA_DIGEST_LENGTH);
//	SHA1(r1, length, r2);
//	element_from_hash(h, r2, SHA_DIGEST_LENGTH);
//
//	free(r1);
//	free(r2);
//}


//random string generation


char * rand_str(int in_len)
{
  char *__r = (char *)malloc(in_len + 1);

  int i;

  if (__r == 0)
  {
    return 0;
  }

  srand(time(NULL) + rand());    //初始化随机数的种子
  for (i = 0; i  < in_len; i++)
  {
    __r[i] = rand()%94+32;      //控制得到的随机数为可显示字符
  }

  __r[i] = 0;

  return __r;
}


/*
Generate a system params and corresponding master secret key, and
assign the *params and *msk pointers to them. The space used may be
later freed by calling Free_system_params(system_params_t* params) and
Free_system_msk (system_msk_t* msk).
*/
void setup( PPUAKA_params_t** params,PPUAKA_msk_t** msk)
{

	/* initialize */
	*params = (PPUAKA_params_t*)malloc(sizeof(PPUAKA_params_t));
	*msk = (PPUAKA_msk_t*)malloc(sizeof(PPUAKA_msk_t));

	(*params)->pairing_desc = strdup(TYPE_A_PARAMS);
	pairing_init_set_buf((*params)->e, (*params)->pairing_desc, strlen((*params)->pairing_desc));    //Initialize pairing from parameters


	element_init_G1((*params)->g,          (*params)->e);
	element_init_G2((*params)->h,          (*params)->e);
	//element_init_G1((*params)->q,          (*params)->e);
	element_init_G1((*params)->g_hat_alpha,(*params)->e);
	element_init_Zr((*msk)->alpha,         (*params)->e);

	/* compute */

 	element_random((*msk)->alpha);
	element_random((*params)->g);
	element_random((*params)->h);

	element_pow_zn((*params)->g_hat_alpha, (*params)->g,(*msk)->alpha);

	//test

//	printf("*****************************************************************************\n");
//	printf("setup--output: pairing desc is %s\n", (*params)->pairing_desc);
//	element_printf("setup--output: g is %B\n", (*params)->g);
//	element_printf("setup--output: h is %B\n", (*params)->h);
//	element_printf("setup--output: g hat alpha is %B\n", (*params)->g_hat_alpha);
//	element_printf("setup--output: msk key is %B\n", (*msk)->alpha);
//	printf("*****************************************************************************\n");

	//test over

}

/*
Generate the psedonym and keypairs for user.
*/

void user_register (PPUAKA_user_keypair_t** keypair,
					PPUAKA_user_pseud_t** pseud,
					PPUAKA_params_t* params,
					PPUAKA_msk_t* msk,
					PPUAKA_user_realid_t* realid)
{
	element_t r1, r2;
	char* ch;
	time_t rawtime;
	struct tm* timeinfo;



	*keypair = (PPUAKA_user_keypair_t*)malloc(sizeof(PPUAKA_user_keypair_t));
	*pseud = (PPUAKA_user_pseud_t*)malloc(sizeof(PPUAKA_user_pseud_t));


	(*pseud)->pid = (char*)malloc(SHA_DIGEST_LENGTH+2);
	(*pseud)->timestamp = (char*)malloc(100);


	element_init_G1((*keypair)->pub,   params->e);
	element_init_G1((*keypair)->prv,   params->e);
	element_init_G1(r1,  params->e);
	element_init_G1(r2,  params->e);


	ch = malloc(SHA_DIGEST_LENGTH+2);
	memset(ch, 0, SHA_DIGEST_LENGTH+2);

	//solve ID bug
	//realid->rid

	//SHA1((unsigned char*)(realid->rid), strlen(realid->rid), ch);
	//(*pseud)->pid = (char*)ch;
	ch = rand_str(SHA_DIGEST_LENGTH+2);
	(*pseud)->pid = ch;

	time (&rawtime);
	timeinfo = localtime ( &rawtime );
	(*pseud)->timestamp = asctime (timeinfo);

	//test
//	printf("*****************************************************************************\n");
//
//	printf ( "register--output: The current date/time is: %s\n", asctime (timeinfo) );
//	printf("register--output: real id is %s.\n", realid->rid);
//	printf ( "register--output: The psedu is: %s\n", (*pseud)->pid);
//	printf ( "register--output: The timestamp is: %s\n", (*pseud)->timestamp);
	//test over

	element_from_string_1(r1, (*pseud)->pid);

//	printf("register--output------test: pid is %s\n", (*pseud)->pid);
//	printf("register--output------test: pid is %s\n", (char*)(*pseud)->pid);

	element_pow_zn (r2, r1, msk->alpha);

	//test
//	element_printf("in_fun:r1 is %B\n", r1);
//	element_printf("in_fun:r2 is %B\n", r2);
	//test over

	element_set((*keypair)->pub, r1);
	element_set((*keypair)->prv, r2);

//	element_printf("publickey  is %B\n", r1);


	//test
//	printf("register--output: pid is %s\n", (*pseud)->pid);
//	printf("register--output: ts is %s\n", (*pseud)->timestamp);
//	element_printf("register--output: r1 is %B\n", r1);
//	element_printf("register--output: user_pubkey is %B\n", (*keypair)->pub);
//	element_printf("register--output: user_prvkey is %B\n", (*keypair)->prv);
//	printf("*****************************************************************************\n");

	element_clear(r1);
	element_clear(r2);
}


/*
Generate first hint.
*/
void user_hint_gen (PPUAKA_user_hint_t** hint,
					PPUAKA_user_message_t** msg,
					PPUAKA_params_t* params,
					PPUAKA_user_pseud_t* pseud,
					PPUAKA_session_id_t* sessionid,
					unsigned int index
					)
{
	*hint = (PPUAKA_user_hint_t*)malloc(sizeof(PPUAKA_user_hint_t));
	*msg = (PPUAKA_user_message_t*)malloc(sizeof(PPUAKA_user_message_t));

	(*msg)->sid = sessionid->sid;
	(*msg)->pid = pseud->pid;
	(*msg)->index = index;
	element_init_G1((*msg)->hint_first, params->e);
	element_init_Zr((*hint)->beta,params->e);
	element_init_G1((*hint)->hint_first, params->e);


	element_random((*hint)->beta);
	element_pow_zn((*hint)->hint_first, params->g, (*hint)->beta);
	element_set((*msg)->hint_first, (*hint)->hint_first);

//	element_printf("hint_gen: hint is %B------------------------\n", ((*hint)->hint_first));

	//test start
//	element_printf("in_function:beta is %B\n", (*hint)->beta);
//	element_printf("in_function:hint_1 is %B\n", (*hint)->hint_first);
//	element_printf("in_function:hint_1 is %B\n", (*msg)->hint_first);
	//test end
}



/*
Generate key materials, including left key, right key, and second key hint.
*/
void key_material_gen  (PPUAKA_user_key_material_t** material,
						PPUAKA_user_message_t** msg_2,
						PPUAKA_params_t* params,
						PPUAKA_user_pseud_t* pseud,
						PPUAKA_user_message_t* msg_left,
						PPUAKA_user_message_t* msg_right,
						PPUAKA_user_hint_t* hint,
						unsigned int index)
{

	*material  = (PPUAKA_user_key_material_t*)malloc(sizeof(PPUAKA_user_key_material_t));
	*msg_2  = (PPUAKA_user_message_t*)malloc(sizeof(PPUAKA_user_message_t));



	element_init_G1((*material)->left_key, params->e);
	element_init_G1((*material)->right_key, params->e);
	element_init_G1((*material)->hint_plus, params->e);
	element_init_G1((*msg_2)->hint_first, params->e);

	(*msg_2)->sid = msg_left->sid;
	(*msg_2)->pid = pseud->pid;
	(*msg_2)->index = index;

	element_pow_zn((*material)->left_key, msg_left->hint_first, hint->beta);
	element_pow_zn((*material)->right_key, msg_right->hint_first, hint->beta);
	element_div((*material)->hint_plus, (*material)->right_key, (*material)->left_key);

	element_set ((*msg_2)->hint_first, (*material)->hint_plus);

}


/*
Generate signature
*/
void sign_gen ( PPUAKA_user_signature_t** sign,
				PPUAKA_user_message_t* msg,
				PPUAKA_params_t* params,
				PPUAKA_user_keypair_t* keypair,
				PPUAKA_user_hint_t* hint,
				int flag	//define the round number. one OR two
				)
{


	*sign = (PPUAKA_user_signature_t*)malloc(sizeof(PPUAKA_user_signature_t));
	element_t tmp1, tmp2;
	char * msg_to_char;
	char * element_temp;
	//GByteArray* b;
	if(flag == 1)
	{

	element_init_G1((*sign)->u, params->e);
	element_init_G1((*sign)->h, params->e);
	element_init_G1((*sign)->v, params->e);
	element_init_G1(tmp1, params->e);
	element_init_G1(tmp2, params->e);

	//test
//	printf("test: sid %s\n", msg->sid);
//	printf("test: pid %s\n", msg->pid);
//	element_printf("test: hint is %B\n", msg->hint_first);

//	//msg to char
//	b = g_byte_array_new();
//	b = PPUAKA_msg_serialize(msg);
//	msg_to_char = (char*)malloc (sizeof(GByteArray));
//	msg_to_char = (char*)(b->data);
//	element_from_string_1((*sign)->h, (char*)msg_to_char);

	//msg to char

	//test

	//test end

	msg_to_char = (char*)malloc (400);
	element_temp = (char*)malloc (140);
	memset(msg_to_char, 0, 400);
	memset(element_temp, 0, 140);
	strcpy(msg_to_char, msg->sid);
	strcat(msg_to_char, msg->pid);
//	printf("round1: sign: input: msg->pid is %s\n", msg->pid);
//	fflush(stdout);
	element_to_bytes((unsigned char*)element_temp, msg->hint_first);
	//printf("test---------------------------------------------------------------------------%d\n",num);
	strcat(msg_to_char, element_temp);

	//printf("TEST1111-----------------------------------%s\n", msg_to_char);
	element_from_string_1((*sign)->h, msg_to_char);

	element_printf("hj is %B\n", (*sign)->h);

	element_set((*sign)->u, msg->hint_first);
	element_pow_zn(tmp1, keypair->pub, hint->beta);
	element_pow_zn(tmp2, keypair->prv, (*sign)->h);
	element_mul((*sign)->v, tmp1, tmp2);


	//test
	element_printf("round 1: output:sig-u is %B\n", (*sign)->u);
	element_printf("round 1: output:sig-h is %B\n", (*sign)->h);
	element_printf("round 1: output:sig-v is %B\n", (*sign)->v);
	//test over

	free(msg_to_char);
	free(element_temp);
	element_clear(tmp1);
	element_clear(tmp2);
	}

	else
	{
		unsigned char* u_to_char;
		element_t y;

	element_init_G1((*sign)->u, params->e);
	element_init_G1((*sign)->h, params->e);
	element_init_G1((*sign)->v, params->e);
	element_init_G1(tmp1, params->e);
	element_init_G1(tmp2, params->e);
	element_init_Zr(y, params->e);

	element_random(y);
	element_pow_zn((*sign)->u, params->g, y);

	//U to char
	u_to_char = malloc (element_length_in_bytes((*sign)->u));
	printf("test: %d\n", element_length_in_bytes((*sign)->u));
	memset(u_to_char, 0, element_length_in_bytes((*sign)->u));
	element_to_bytes(u_to_char, (*sign)->u);

	//msg to char
//	b = g_byte_array_new();
//	b = PPUAKA_msg_serialize(msg);
//	msg_to_char = malloc (sizeof(GByteArray));
//	msg_to_char = (char*)(b->data);
	msg_to_char = (char*)malloc (400);
	element_temp = (char*)malloc (140);
	memset(msg_to_char, 0, 400);
	strcpy(msg_to_char, msg->sid);
	strcat(msg_to_char, msg->pid);
	memset(element_temp, 0, 140);
	element_to_bytes((unsigned char*)element_temp, msg->hint_first);
	strcat(msg_to_char, element_temp);
	//element_from_string_1((*sign)->h, msg_to_char);


	//combine u_to_char and msg_to_char
	strcat(msg_to_char, (char*)(u_to_char));

	element_from_string_1((*sign)->h, msg_to_char);

	element_pow_zn(tmp1, keypair->pub, y);
	element_pow_zn(tmp2, keypair->prv, (*sign)->h);
	element_mul((*sign)->v, tmp1, tmp2);

	//test
		element_printf("round 2: output:sig-u is %B\n", (*sign)->u);
		element_printf("round 2: output:sig-h is %B\n", (*sign)->h);
		element_printf("round 2: output:sig-v is %B\n", (*sign)->v);
	//test over


	element_clear(y);

	element_clear(tmp1);
	element_clear(tmp2);
	free(u_to_char);
	}
}

/*
Verify signature
*/

int verify_r1(PPUAKA_params_t* params,
				PPUAKA_user_message_t* msg_left,
				PPUAKA_user_message_t* msg_right,
				PPUAKA_user_signature_t* sign_left,
				PPUAKA_user_signature_t* sign_right
				)

{
	int result;
	char* msg_to_char_1;
	char* msg_to_char_2;
	char* element_temp_1;
	char* element_temp_2;
	//GByteArray* b_1;
	//GByteArray* b_2;
		element_t publickey_1, publickey_2;
		element_t h1,h2;
		element_t sign_mul;
		element_t left, right;
		element_t tmp1, tmp2;
		element_t tmp_e_1, tmp_e_2;


		element_init_G1(publickey_1, params->e);
		element_init_G1(publickey_2, params->e);
		element_init_G1(h1, params->e);
		element_init_G1(h2, params->e);
		element_init_G1(sign_mul, params->e);
		element_init_GT(left,  params->e);
		element_init_GT(right, params->e);

		element_init_G1(tmp1, params->e);
		element_init_G1(tmp2, params->e);
		element_init_GT(tmp_e_1, params->e);
		element_init_GT(tmp_e_2, params->e);

		element_from_string_1(publickey_1, msg_left->pid);
		element_from_string_1(publickey_2, msg_right->pid);

		//test
//		printf("*****************************************************************************\n");
//
//		printf("Round 2: Verify: Left: msg: slid: %s\n", msg_left->sid);
//		printf("Round 2: Verify: Left: msg: pid: %s\n", msg_left->pid);
//		element_printf("Round 2: Verify: msg: hint 1 :  %B\n",msg_left->hint_first);
//		element_printf("Round 2: Verify: sign: u: %B\n", sign_left->u);
//		element_printf("Round 2: Verify: sign: h: %B\n", sign_left->h);
//		element_printf("Round 2: Verify: sign: v: %B\n", sign_left->v);
//
//		printf("Round 2: Verify: Right: msg: sid: %s.\n", msg_right->sid);
//		printf("Round 2: Verify: Right: msg: pid: %s.\n", msg_right->pid);
//		element_printf("Round 2: Verify: Right: msg: hint 1: %B.\n",msg_right->hint_first);
//		element_printf("Round 2: Verify: Right: sign: u: %B.\n", sign_right->u);
//		element_printf("Round 2: Verify: Right: Sign: h: %B.\n", sign_right->h);
//		element_printf("Round 2: Verify: Right: Sign: v: %B.\n", sign_right->v);
//
//		printf("*****************************************************************************\n");

		//test end


		//msg to char
			msg_to_char_1 = (char*)malloc (400);
			element_temp_1 = (char*)malloc (140);
			memset(msg_to_char_1, 0, 400);
			memset(element_temp_1, 0, 140);

			strcpy(msg_to_char_1, msg_left->sid);
			strcat(msg_to_char_1, msg_left->pid);
			element_to_bytes((unsigned char*)element_temp_1, msg_left->hint_first);
			strcat(msg_to_char_1, element_temp_1);

			//printf("TEST222222222-----------------------------------%s\n", msg_to_char_1);
			element_from_string_1(h1, msg_to_char_1);

			free(msg_to_char_1);
			free(element_temp_1);

//			element_printf("left hj is % B\n", h1 );

			msg_to_char_2 = (char*)malloc (400);
			element_temp_2 = (char*)malloc (140);
			memset(msg_to_char_2, 0, 400);
			memset(element_temp_2, 0, 140);

			strcpy(msg_to_char_2, msg_right->sid);
			strcat(msg_to_char_2, msg_right->pid);
			element_to_bytes((unsigned char*)element_temp_2, msg_right->hint_first);
			strcat(msg_to_char_2, element_temp_2);
			element_from_string_1(h2, msg_to_char_2);

//			element_printf("right hj is % B\n", h2 );

			free(msg_to_char_2);
			free(element_temp_2);

//			element_printf("hj is % B\n", h2 );




		//left
		element_mul(sign_mul, sign_left->v, sign_right->v);
		pairing_apply(left, params->g, sign_mul, params->e);


		//right
		element_pow_zn(tmp1, params->g_hat_alpha, h1);
		element_pow_zn(tmp2, params->g_hat_alpha, h2);
		element_mul(tmp1, msg_left->hint_first, tmp1);
		element_mul(tmp2, msg_right->hint_first, tmp2);
		pairing_apply(tmp_e_1, publickey_1, tmp1, params->e);
		pairing_apply(tmp_e_2, publickey_2, tmp2, params->e);
		element_mul(right, tmp_e_1, tmp_e_2);
//
//				element_printf("left is %B\n", left);
//				element_printf("right is %B\n", right);

		result = element_cmp(left, right);	//same output 0, else 1.
		return result;

		element_clear(publickey_1);
		element_clear(publickey_2);
		element_clear(h1);
		element_clear(h2);
		element_clear(sign_mul);
		element_clear(left);
		element_clear(right);
		element_clear(tmp1);
		element_clear(tmp2);
		element_clear(tmp_e_1);
		element_clear(tmp_e_2);


}


int verify_r1_test(PPUAKA_params_t* params,
				PPUAKA_user_message_t* msg_left,
				PPUAKA_user_message_t* msg_right,
				PPUAKA_user_signature_t* sign_left,
				PPUAKA_user_signature_t* sign_right
				)

{
	int result;
	char* msg_to_char_1;
	char* msg_to_char_2;
	char* element_temp_1;
	char* element_temp_2;
	//GByteArray* b_1;
	//GByteArray* b_2;
		element_t publickey_1, publickey_2;
		element_t h1,h2;
		element_t sign_mul;
		element_t left, right;
		element_t tmp1, tmp2;
		element_t tmp_e_1, tmp_e_2;


		element_init_G1(publickey_1, params->e);
		element_init_G1(publickey_2, params->e);
		element_init_G1(h1, params->e);
		element_init_G1(h2, params->e);
		element_init_G1(sign_mul, params->e);
		element_init_GT(left,  params->e);
		element_init_GT(right, params->e);

		element_init_G1(tmp1, params->e);
		element_init_G1(tmp2, params->e);
		element_init_GT(tmp_e_1, params->e);
		element_init_GT(tmp_e_2, params->e);

		element_from_string_1(publickey_1, msg_left->pid);
		element_from_string_1(publickey_2, msg_right->pid);


		//test
		printf("*****************************************************************************\n");

//		printf("Round 2: Verify: Left: msg: slid: %s\n", msg_left->sid);
//		printf("Round 2: Verify: Left: msg: pid: %s\n", msg_left->pid);
//		element_printf("Round 2: Verify: Left: msg: hint 1 :  %B\n",msg_left->hint_first);
//		element_printf("Round 2: Verify: Left: pubkey %B\n", publickey_1);
//		element_printf("Round 2: Verify: Left: sign: u: %B\n", sign_left->u);
//		element_printf("Round 2: Verify: Left: sign: h: %B\n", sign_left->h);
//		element_printf("Round 2: Verify: Left: sign: v: %B\n", sign_left->v);

		element_printf("Round 2: Verify: Right: params: g %B\n", params->g);
		element_printf("Round 2: Verify: Right: params: h %B\n", params->h);
		element_printf("Round 2: Verify: Right: params: g_hat_alpha %B\n", params->g_hat_alpha);

		printf("Round 2: Verify: Right: msg: sid: %s.\n", msg_right->sid);
		printf("Round 2: Verify: Right: msg: pid: %s.\n", msg_right->pid);
		element_printf("Round 2: Verify: Right: msg: hint 1: %B.\n",msg_right->hint_first);
		element_printf("Round 2: Verify: Right: pubkey %B\n", publickey_2);
		element_printf("Round 2: Verify: Right: sign: u: %B.\n", sign_right->u);
		element_printf("Round 2: Verify: Right: Sign: h: %B.\n", sign_right->h);
		element_printf("Round 2: Verify: Right: Sign: v: %B.\n", sign_right->v);

		printf("*****************************************************************************\n");

		//test end


		//msg to char
			msg_to_char_1 = (char*)malloc (200);
			element_temp_1 = (char*)malloc (129);
			strcpy(msg_to_char_1, msg_left->sid);
			strcat(msg_to_char_1, msg_left->pid);
			element_to_bytes((unsigned char*)element_temp_1, msg_left->hint_first);
			strcat(msg_to_char_1, element_temp_1);
			element_from_string_1(h1, msg_to_char_1);

			msg_to_char_2 = (char*)malloc (200);
			element_temp_2 = (char*)malloc (129);
			strcpy(msg_to_char_2, msg_right->sid);
			strcat(msg_to_char_2, msg_right->pid);
			element_to_bytes((unsigned char*)element_temp_2, msg_right->hint_first);
			strcat(msg_to_char_2, element_temp_2);
			element_from_string_1(h2, msg_to_char_2);


		//left
		//element_mul(sign_mul, sign_left->v, sign_right->v);
		pairing_apply(left, params->g, sign_right->v, params->e);
		element_printf("left is %B\n", left);

		//right
		element_pow_zn(tmp2, params->g_hat_alpha, h2);
		//element_pow_zn(tmp2, params->g_hat_alpha, h2);
		element_mul(tmp2, msg_right->hint_first, tmp2);
		//element_mul(tmp2, msg_right->hint_first, tmp2);
		pairing_apply(right, publickey_2, tmp2, params->e);
		//pairing_apply(tmp_e_2, publickey_2, tmp2, params->e);
		//element_mul(right, tmp_e_1, tmp_e_2);
		element_printf("right is %B\n", right);

		result = element_cmp(left, right);	//same output 0, else 1.

	return result;
}

int verify_r2(PPUAKA_params_t* params,
			PPUAKA_user_message_t** msg_2_keygen,
			PPUAKA_user_signature_t** sign_2_keygen,
			int UserNum	)
{

	int i;
	int result;

	char* msg_to_char [UserNum-1];
	char* element_temp [UserNum-1];
	//GByteArray* b[UserNum-1];

	element_t publickey [UserNum-1];
	element_t h[UserNum-1];
	element_t tmp[UserNum-1];
	element_t tmp_e[UserNum-1];
	element_t sign_mul;
	element_t left, right;


	element_init_G1(sign_mul, params->e);
	element_init_GT(left,  params->e);
	element_init_GT(right, params->e);

	element_set1(sign_mul);
	element_set1(right);

	for (i =1; i<= UserNum-1; i++)
	{
		unsigned char* u_to_char;

		element_init_G1(publickey[i-1], params->e);
		element_init_G1(h[i-1], params->e);
		//element_init_G1(sign_mul[i-1], params->e);
		element_init_G1(tmp[i-1], params->e);
		element_init_GT(tmp_e[i-1], params->e);

//		element_printf("keygen_pid recover is %s\n", msg_2_keygen[i-1]->pid);
//		element_printf("keygen_sign_v is %B\n", sign_2_keygen[i-1]->v);

		element_from_string_1(publickey[i-1], msg_2_keygen[i-1]->pid);

		//U to char
		u_to_char = malloc (element_length_in_bytes(sign_2_keygen[i-1]->u));
		memset(u_to_char, 0, element_length_in_bytes(sign_2_keygen[i-1]->u));
		element_to_bytes(u_to_char, sign_2_keygen[i-1]->u);

		//msg to char
			//		b[i-1] = g_byte_array_new();
			//		b[i-1] = PPUAKA_msg_serialize(msg_2_keygen[i-1]);
			//		msg_to_char[i-1] = malloc (sizeof(GByteArray));
			//		msg_to_char[i-1] = (char*)(b[i-1]->data);
		msg_to_char[i-1] = (char*)malloc(400);
		element_temp[i-1]= (char*)malloc (140);
		memset(msg_to_char [i-1], 0, 400);
		memset(element_temp [i-1], 0, 140);


		strcpy(msg_to_char[i-1], msg_2_keygen[i-1]->sid);
		strcat(msg_to_char[i-1], msg_2_keygen[i-1]->pid);
		element_to_bytes((unsigned char*)element_temp[i-1], msg_2_keygen[i-1]->hint_first);
		strcat(msg_to_char[i-1], element_temp[i-1]);

		//combine u_to_char and msg_to_char
		strcat(msg_to_char[i-1], (char*)(u_to_char));

		element_from_string_1(h[i-1], msg_to_char[i-1]);


		//sign mul
		element_printf("sign_mul is %B\n", sign_mul);
		element_mul(sign_mul, sign_mul, sign_2_keygen[i-1]->v);
		element_printf("v is %B\n", sign_2_keygen[i-1]->v);
		element_printf("sign_mul is %B\n", sign_mul);


		element_pow_zn(tmp[i-1], params->g_hat_alpha, h[i-1]);
		element_mul(tmp[i-1], sign_2_keygen [i-1]->u, tmp[i-1]);
		pairing_apply(tmp_e[i-1], publickey[i-1], tmp[i-1], params->e);

		free(u_to_char);
	}

	//right
	for (i =1; i<=UserNum-1;i++)
		{

			element_mul(right, right, tmp_e[i-1]);
		}

	//left
		pairing_apply(left, params->g, sign_mul, params->e);


		result = element_cmp(left, right);	//same output 0, else 1.

	return result;

}


void keygen(PPUAKA_session_key_t** sessionkey,
			PPUAKA_params_t* params,
			PPUAKA_user_key_material_t* key_material,
			PPUAKA_user_message_t** msg_2_keygen,
			int UserNum)
{
	int i;
	int verify_result;

	*sessionkey =  (PPUAKA_session_key_t*)malloc(sizeof(PPUAKA_session_key_t));

	element_t rec_right [UserNum-1];

	element_init_G1((*sessionkey)->ssk,params->e);
	element_set1((*sessionkey)->ssk);

	for(i =2; i<=UserNum; i++)
	{
		element_init_G1(rec_right[i-2], params->e);

		if (i ==2 )
		element_mul(rec_right[i-2], msg_2_keygen[i-2]->hint_first, key_material->right_key);

		else
		element_mul(rec_right[i-2], msg_2_keygen[i-2]->hint_first, rec_right[i-3]);
	};

	element_printf("left key is %B\n", key_material->left_key);
	element_printf("recover left key is %B\n", rec_right[UserNum-2]);
	verify_result = element_cmp(rec_right[UserNum-2], key_material->left_key);

	if (verify_result)
		printf("The signature verification is fail!\n");
	else
		for (i =2; i<=UserNum; i++)
		{
			element_printf("session_key is %B\n", (*sessionkey)->ssk);

			element_mul((*sessionkey)->ssk, (*sessionkey)->ssk, rec_right[i-2]);
		}

	element_printf("session_key is %B\n", (*sessionkey)->ssk);

}


