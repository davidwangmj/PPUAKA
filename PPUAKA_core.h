/*
 * PPUAKA_core.h
 *
 *  Created on: 2017-4-22
 *      Author: MJWang
 */

#ifndef PPUAKA_CORE_H_
#define PPUAKA_CORE_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include <openssl/sha.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <pbc_test.h>

#include "PPUAKA_lib.h"
#include "PPUAKA_common.h"

// parameters of pairing e
#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"

void element_from_string_1( element_t h, char* s );
char * rand_str(int in_len);

void setup( PPUAKA_params_t** params,PPUAKA_msk_t** msk);
void user_register (PPUAKA_user_keypair_t** keypair,
					PPUAKA_user_pseud_t** pseud,
					PPUAKA_params_t* params,
					PPUAKA_msk_t* msk,
					PPUAKA_user_realid_t* realid);
void user_hint_gen (PPUAKA_user_hint_t** hint,
					PPUAKA_user_message_t** msg,
					PPUAKA_params_t* params,
					PPUAKA_user_pseud_t* pseud,
					PPUAKA_session_id_t* sessionid,
					unsigned int index);
void key_material_gen  (PPUAKA_user_key_material_t** material,
						PPUAKA_user_message_t** msg_2,
						PPUAKA_params_t* params,
						PPUAKA_user_pseud_t* pseud,
						PPUAKA_user_message_t* msg_left,
						PPUAKA_user_message_t* msg_right,
						PPUAKA_user_hint_t* hint,
						unsigned int index);
void sign_gen ( PPUAKA_user_signature_t** sign,
				PPUAKA_user_message_t* msg,
				PPUAKA_params_t* params,
				PPUAKA_user_keypair_t* keypair,
				PPUAKA_user_hint_t* hint,
				int flag	//define the round number. one OR two
				);
int verify_r1(PPUAKA_params_t* params,
				PPUAKA_user_message_t* msg_left,
				PPUAKA_user_message_t* msg_right,
				PPUAKA_user_signature_t* sign_left,
				PPUAKA_user_signature_t* sign_right
				);

int verify_r1_test(PPUAKA_params_t* params,
				PPUAKA_user_message_t* msg_left,
				PPUAKA_user_message_t* msg_right,
				PPUAKA_user_signature_t* sign_left,
				PPUAKA_user_signature_t* sign_right
				);


int verify_r2(PPUAKA_params_t* params,
			PPUAKA_user_message_t** msg_2_keygen,
			PPUAKA_user_signature_t** sign_2_keygen,
			int UserNum);


void keygen(PPUAKA_session_key_t** sessionkey,
			PPUAKA_params_t* params,
			PPUAKA_user_key_material_t* key_material,
			PPUAKA_user_message_t** msg_2_keygen,
			int UserNum);

#endif /* PPUAKA_CORE_H_ */
