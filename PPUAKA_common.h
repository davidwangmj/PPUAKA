/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * Include glib.h and pbc.h before including this file. Note that this
 * file should be included at most once.
*/

/* 		data function definition		*/

#ifndef PPUAKA_COMMON_H_
#define PPUAKA_COMMON_H_

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <pbc.h>
#include "PPUAKA_lib.h"


char*       suck_file_str( char* file );
char*       suck_stdin();
GByteArray* suck_file( char* file );

void        spit_file( char* file, GByteArray* b, int free );

void die(char* fmt, ...);

/* 		operation function definition		*/

GByteArray* aes_128_cbc_encrypt( GByteArray* pt, element_t k );

GByteArray* aes_128_cbc_decrypt( GByteArray* ct, element_t k );

/***********************************************************
   serialize function
*********************************************************  */

GByteArray* PPUAKA_params_serialize( PPUAKA_params_t* params);
GByteArray* PPUAKA_msk_serialize( PPUAKA_msk_t* msk );
GByteArray* PPUAKA_keypair_serialize( PPUAKA_user_keypair_t* keypair );
GByteArray* PPUAKA_realid_serialize( PPUAKA_user_realid_t* realid );
GByteArray* PPUAKA_pseud_serialize( PPUAKA_user_pseud_t* pseud );
GByteArray* PPUAKA_sessionid_serialize( PPUAKA_session_id_t* sessionid );
GByteArray* PPUAKA_hint_serialize( PPUAKA_user_hint_t* hint );
GByteArray* PPUAKA_msg_serialize( PPUAKA_user_message_t* msg );
GByteArray* PPUAKA_sign_serialize( PPUAKA_user_signature_t* sign );
GByteArray* PPUAKA_key_material_serialize( PPUAKA_user_key_material_t* key_material );
GByteArray* PPUAKA_session_key_serialize( PPUAKA_session_key_t* session_key );
/*
  Also exactly what it seems. If free is true, the GByteArray passed
  in will be free'd after it is read.
*/
PPUAKA_params_t* PPUAKA_params_unserialize( GByteArray* b, int free );
PPUAKA_msk_t* PPUAKA_msk_unserialize( PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_user_keypair_t* PPUAKA_keypair_unserialize( PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_user_realid_t* PPUAKA_realid_unserialize(GByteArray* b, int free );
PPUAKA_user_pseud_t* PPUAKA_pseud_unserialize(GByteArray* b, int free );
PPUAKA_session_id_t* PPUAKA_sessionid_unserialize (GByteArray* b, int free);
PPUAKA_user_hint_t* PPUAKA_hint_unserialize(PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_user_message_t* PPUAKA_msg_unserialize(PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_user_signature_t* PPUAKA_sign_unserialize(PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_user_key_material_t* PPUAKA_key_material_unserialize(PPUAKA_params_t* params, GByteArray* b, int free );
PPUAKA_session_key_t* PPUAKA_session_key_unserialize(PPUAKA_params_t* params, GByteArray* b, int free );
/*
  Again, exactly what it seems.
*/
void PPUAKA_params_free( PPUAKA_params_t* params);
void PPUAKA_msk_free( PPUAKA_msk_t* msk );
void PPUAKA_keypair_free( PPUAKA_user_keypair_t* keypair);
void PPUAKA_realid_free( PPUAKA_user_realid_t* realid );
void PPUAKA_pseud_free( PPUAKA_user_pseud_t* pseud );
void PPUAKA_sessionid_free (PPUAKA_session_id_t * sessionid);
void PPUAKA_hint_free( PPUAKA_user_hint_t* hint );
void PPUAKA_msg_free( PPUAKA_user_message_t* msg );
void PPUAKA_sign_free( PPUAKA_user_signature_t* sign );
void PPUAKA_key_material_free( PPUAKA_user_key_material_t* key_material );
void PPUAKA_session_key_free( PPUAKA_session_key_t* session_key );

#endif /* PPUAKA_COMMON_H_ */



