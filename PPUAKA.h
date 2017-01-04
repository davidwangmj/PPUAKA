/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 * 
 * PPUAKA.c
 */
 
#include <string.h>
#include "pbc.h"

/* **********************************************************
   DEBUG having the debug flag turned on spews out lots of
   debugging output.
*********************************************************  */
#define DEBUG 1

/* 		structures defination		*/

/* **********************************************************
   SYSTEM PARAMS--
   Stores the:

*********************************************************  */
typedef struct system_params_s {
	char *pairFileName;
	pairing_t pairing;
	element_t g;
	element_t h;  //h是否有用
	element_t g_hat_alpha; //gs
}* system_params_t;


/* **********************************************************
   SYSTEM MASTER KEY
*********************************************************  */
typedef struct system_msk_s {
	element_t alpha; //s
		
}* system_msk_t;


/* **********************************************************
   USER INFORMATIONS
   Stores the:
   Real identity
   Pseudonym, timestamp
   public key
   private key   
*********************************************************  */

typedef struct user_realid_s {
	unsigned char* rid;
	
}* user_realid_t;

typedef struct user_pseud_s {
	unsigned char* pid;  
	time_t timestamp;	
}* user_pseud_t;


typedef struct user_keypair_s{
	element_t pub_key;	//G1
	element_t prv_key;	//G1
	
}* user_keypair_t;

/* **********************************************************
   SESSION KEY GENERATION MATERIALS
   Stores the:
   user hint;
   user hint_plus;
   left/right key;
   *********************************************************  */

typedef struct user_hint_s {
	element_t beta;		//xi
	element_t hint;
}* user_hint_t;


typedef struct user_key_material_s {
	element_t left_key;
	element_t right_key;
	element_t hint_plus;
}* user_key_material_t;

typedef struct message_s {
	unsigned char* sid;
	unsigned char* pid;
	int index;
	element_t hint;
}* message_t;

typedef struct session_key_s {
	element_t k;
}* session_key_t;

/* **********************************************************
   SIGNATURE   
*********************************************************  */

typedef struct signature_s {
	element_t u;
	element_t h; //hashed Msg
	element_t v;
}* sign_t;


/* 		function defination		*/


/* **********************************************************
   These functions free the memory associated with various 
   structures.  Note that the pointer you pass in will not
   be freed--you must free it manually to prevent freeing
   stack memory.
********************************************************** */
void Free_system_params(system_params_t params);
void Free_system_msk (system_msk_t msk);
void Free_user_realid (user_realid_t realid);
void Free_user_pseud (user_pseud_t pseud);
void Free_user_keypair (user_keypair_t keypair);
void Free_user_hint (user_hint_t hint);
void Free_user_key_material (user_key_material_t material);
void Free_user_signature (sign_t sign);
void Free_user_session_key (session_key_t sk);

/* **********************************************************
   Hash function H1, H2, H3
*********************************************************  */
void element_from_string_1( element_t h, unsigned char* s );
void element_from_string_2( element_t h, char* s, element_t t );
void element_from_string_3( element_t h, element_t t );


/* **********************************************************
   Generate a system params and corresponding master secret key, and
	assign the *params and *msk pointers to them. The space used may be
	later freed by calling Free_system_params(system_params_t* params) and
	Free_system_msk (system_msk_t* msk).
*********************************************************  */

void System_setup ( system_params_t *params,
					system_msk_t *msk,
					char *pairFileName);

/* **********************************************************
   Stores the system parameters and master secret key to a file.
*********************************************************  */

void StoreParams (char* ParamsFileName, system_params_t params);
void LoadParams	 (char* ParamsFileName, system_params_t* params);
					
void StoreMSK (char* MSKFileName, system_mks_t msk);
void LoadMSK (char* MSKFileName, system_msk_t* msk);


/* **********************************************************
   Generate the psedonym and keypairs for user.
*********************************************************  */

void User_keypair_gen (user_keypair_t *keypair,
						user_pseud_t *pseud,
						system_params_t params,  
						user_realid_t realid);
						

/* **********************************************************
   Generate first hint.
*********************************************************  */
						
void User_hint_gen (user_hint_t *userhint,
					system_params_t params,
					);
					
/* **********************************************************
   Generate key materials, including left key, right key, 
   and second key hint.
*********************************************************  */					

void User_key_material_gen (user_key_material_t * material,
							user_pseud_t pseud,
							system_params_t params，
							user_hint_t userhint,
							user_hint_t hint_left,
							user_hint_t hint_right,
							);
							
/* **********************************************************
   Generate signature
*********************************************************  */	

void User_sign (sign_t *sign,
				message_t msg,
				system_params_t params,
				user_keypair_t keypair,
				user_hint_t hint,
				int flag	//用来定义采用哪种签名方式
				);

/* **********************************************************
   Generate Verify signature
*********************************************************  */
int User_verify (sign_t *sign, 
				 system_params_t params
				);

/* **********************************************************
   Generate Sessin key and key seed
*********************************************************  */				

void Session_key_gen (session_key_t * sk,
					   user_key_material_t material,
					   int group_number
					  );
					  
					  
					   

				
				

				
