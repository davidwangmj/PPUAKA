/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * Include glib.h and pbc.h before including this file. Note that this
 * file should be included at most once.
*/

#ifndef PPUAKA_LIB_H_
#define PPUAKA_LIB_H_

/* 		structures definition		*/

//setup
//char*  params_file = "params_key";
//char*  msk_file = "msk_key";


/* **********************************************************
   SYSTEM PARAMS
*********************************************************  */
typedef struct PPUAKA_params_s {
	char *pairing_desc;
	pairing_t e;
	element_t g;	//g1 G1
	element_t h;    //g2 G2
	//element_t q;	//q G2
	element_t g_hat_alpha; //gt  Gt
} PPUAKA_params_t;


/***********************************************************
   SYSTEM MASTER KEY
*********************************************************  */
typedef struct PPUAKA_msk_s {
	element_t alpha; //s
} PPUAKA_msk_t;

/* **********************************************************
   USER INFORMATIONS
   Stores the:char*  params_file = "params_key";
char*  msk_file = "msk_key";
   Real identity
   Pseudonym, timestamp
   public key
   private key
*********************************************************  */

typedef struct PPUAKA_user_realid_s {
	char* rid;
} PPUAKA_user_realid_t;

typedef struct PPUAKA_user_pseud_s {
	char* pid;
	char* timestamp;
} PPUAKA_user_pseud_t;

typedef struct PPUAKA_user_keypair_s{
	element_t pub;	//G1
	element_t prv;	//G1

} PPUAKA_user_keypair_t;


/* **********************************************************
   SESSION KEY GENERATION MATERIALS
   Stores the:
   user hint;
   user hint_plus;char*  params_file = "params_key";
char*  msk_file = "msk_key";
   left/right key;
   session key;
************************************************************/

typedef struct PPUAKA_session_id_s {
	char* sid;
} PPUAKA_session_id_t;

typedef struct PPUAKA_user_hint_s {
	element_t beta;		//X_i
	element_t hint_first;
} PPUAKA_user_hint_t;

typedef struct PPUAKA_user_message_s {
	char* sid;
	char* pid;
	unsigned int index;
	element_t hint_first;
} PPUAKA_user_message_t;

typedef struct PPUAKA_user_signature_s {
	element_t u;
	element_t h; //hashed Msg
	element_t v;
} PPUAKA_user_signature_t;

typedef struct PPUAKA_user_key_material_s {
	element_t left_key;
	element_t right_key;
	element_t hint_plus;
} PPUAKA_user_key_material_t;

typedef struct PPUAKA_session_key_s {
	element_t ssk;
} PPUAKA_session_key_t;

#endif /* PPUAKA_LIB_H_ */


