/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 * 
 * PPUAKA.c
 */
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>

#include "PPUAKA.h"

/* Free Functions*/

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

/* Store and Load Functions*/

void StoreParams (char* ParamsFileName, system_params_t params);
void LoadParams	 (char* ParamsFileName, system_params_t* params);

void StoreMSK (char* MSKFileName, system_msk_t msk);
void LoadMSK (char* MSKFileName, system_msk_t* msk);

/* Hash Functions H1, H2, H3*/

void element_from_string_1( element_t h, char* s )
{
	unsigned char* r;

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
}

void element_from_string_2( element_t h, char* s, element_t t );
{
	int length;
	unsigned char* r1, r2;
	
	length = element_length_in_bytes (t)
	r1 = malloc(length);	
	element_to_bytes(r1, t);
	
	strcat(s,r1); //appends r1 to s
	
	r2 = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r2);
	element_from_hash(h, r2, SHA_DIGEST_LENGTH);

	free(r1);
	free(r2);
}

void element_from_string_3( element_t h, element_t t );
{
	int length;
	unsigned char* r1, r2;
	
	length = element_length_in_bytes (t)
	r1 = malloc(length);	
	element_to_bytes(r1, t);
	
	r2 = malloc(SHA_DIGEST_LENGTH);
	SHA1(r1, length, r2);
	element_from_hash(h, r2, SHA_DIGEST_LENGTH);
	
	free(r1);
	free(r2);
}



/*
Generate a system params and corresponding master secret key, and
assign the *params and *msk pointers to them. The space used may be
later freed by calling Free_system_params(system_params_t* params) and
Free_system_msk (system_msk_t* msk).
*/
void System_setup ( system_params_t *params,
					system_msk_t *msk,
					char *pairFileName);
{
	system_params_t syspar;
	system_msk_t sysmsk;
	
	syspar = pbc_malloc (sizeof(struct system_params_s));
	sysmsk = pbc_malloc (sizeof(struct system_msk_s));
	
	// Setup curve in gbp
	FILE *curveFile = fopen(pairFileName, "r");
	syspar->pairFileName = strdup (pairFileName);
	if(!curveFile){
    printf("%s doesn't exist!  exiting! \n\n", pairFileName);
    return;		
	}
  
	pairing_init_inp_str(syspar->pairing, curveFile);
	fclose(curveFile);	
	
	//Choosing random G & H
	element_init(syspar->g, syspar->pairing->G1);
	element_random(syspar->g);
	element_init(syspar->h, syspar->pairing->G2);
	element_random(syspar->h);	


	//Pick a random s, also the system master key
	element_t alpha;
	element_init_Zr(alpha, syspar->pairing);
	element_random(alpha);
	
	//master key assigment
	element_set (alpha, sysmsk->alpha); //OK?? alpha
	
	//compute gs
	element_pow_zn(syspar->g_hat_alpha, syspar->g, alpha);
	
	*params = syspar;
	*msk = sysmsk;
	element_clear(alpha);
}


/*
Generate the psedonym and keypairs for user.
*/

void User_keypair_gen (user_keypair_t *keypair,
						user_pseud_t *pseud,
						system_params_t params, 
						system_msk_t msk,
						user_realid_t realid);
{
	user_pseud_t psd;
	user_keypair_t kp;
	
	unsigned char* ch;
	element_t r1, r2;
	
	psd = malloc (sizeof(struct user_pseud_s));
	kp = pbc_malloc (sizeof(struct user_keypair_t));
	
	element_init(r1, params->pairing->G1);
	element_init(r2, params->pairing->G1);	
	element_init(kp->pub_key, params->pairing->G1);
	element_init(kp->prv_key, params->pairing->G1);
	
	ch = malloc(SHA_DIGEST_LENGTH);
	SHA1(realid->rid, strlen(realid->rid), ch);	//直接hash真名成为假名，未加随机性（数）
	
	psd->pid = ch;
	psd->timestamp = time (NULL);
	
	
	element_from_string_1(r1, ch);	//直接hash假名字符串，没有用假名结构体
	element_pow_zn (r2, r1, msk->alpha);
	
	element_set(r1, kp->pub_key);
	element_set(r2, kp->prv_key);
	
	
	*pseud = psd;
	*keypair = kp;	
	
	element_clear(r1);
	element_clear(r2);
}
						

/*
Generate first hint.
*/
void User_hint_gen (user_hint_t *userhint,
					system_params_t params,
					);
{
	user_hint_t ht;
	
	ht =  pbc_malloc(sizeof(struct user_hint_s));
	
	element_init_Zr(beta,params->pairing);
	element_init(ht->hint, params->pairing->G1);
	
	element_random(beta);
	element_pow_zn(ht->hint, params->g, ht->beta);
	
	*userhint = ht;
	
}

/*
Generate key materials, including left key, right key, and second key hint.
*/
void User_key_material_gen (user_key_material_t * material,
							user_pseud_t pseud,
							system_params_t params,
							user_hint_t userhint,
							user_hint_t hint_left,
							user_hint_t hint_right,
							);
{
	user_key_material_t ukm;
	
	ukm = pbc_malloc(sizeof(struct user_key_material_s));
	
	element_init(ukm->left_key, params->pairing->G1);
	element_init(ukm->right_key, params->pairing->G1);
	element_init(ukm->hint_plus, params->pairing->G1);
	
	element_pow_zn(ukm->left_key, hint_left->hint, userhint->beta);
	element_pow_zn(ukm->right_key, hint_right->hint, userhint->beta);
	element_div(ukm->hint_plus, ukm->right_key, ukm->left_key);
	
	*material = ukm;
}

/*
Generate signature
*/
void User_sign (sign_t *sign,
				message_t msg,	//??????msg 结构体的序列化
				system_params_t params,
				user_keypair_t keypair,
				user_hint_t ht,
				int flag	//用来定义采用哪种签名方式
				);
{
	sign_t signature;
	element_t tmp;
	
	if(flag == 1)	//第一种签名方式
	{

	element_init(signature->u, params->pairing->G1);
	element_init(signature->h, params->pairing->G1);
	element_init(signature->v, params->pairing->G1);
	element_init(tmp,params->pairing->G1);
	
	element_set(ht->hint,signature->u);
	element_from_string_1(signature->h, unsigned char* msg);
	element_pow_zn(signature->v, keypair->pub_key, ht->beta);
	element_pow_zn(tmp, keypair->prv_key,signature->h);
	element_mul(signature->v, signature->v, tmp);
	
	*sign = signature;
	element_clear(tmp);	
	}
	
	else	//第一种签名方式
	{
	element_t y, tmp;
		
	element_init(signature->u, params->pairing->G1);
	element_init(signature->h, params->pairing->G1);
	element_init(signature->v, params->pairing->G1);
	element_init_Zr(y, params->pairing);
	element_init(tmp, params->pairing->G1);	
	
	element_random(y);
	element_pow_zn(signature->u, params->g, y);
	element_from_string_2(signature->h, unsigned char* msg, signature->u);
	element_pow_zn(signature->v, keypair->pub_key, ht->y);
	element_pow_zn(tmp, keypair->prv_key, signature->h);
	element_mul(signature->v, signature-v, tmp);

	*sign = signature;
	element_clear(y)；
	element_clear(tmp);
	
	}
	
}

/*
Generate Verify signature
*/
int User_verify (sign_t sign, 
				 user_pseud_t pseud,
				 system_params_t params
				);
				
{
	int flag;
}

/*
Generate Sessin key and key seed
*/
void Session_key_gen (session_key_t * sk,
					   user_key_material_t material,
					   int group_number
					  );
{
	int i;
	session_key_t sessionkey,
	
	sessionkey = pbc_malloc(sizeof(struct session_key_s));
	
	element_init(sessionkey->k, params->pairing->G1);
	
	
}

