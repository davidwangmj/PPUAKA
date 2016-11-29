/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 * 
 * PPUAKA.c
 */
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_realid.\n");
		return;	
	}; 
	
	free(realid);
	return;
}

void Free_user_pseud (user_pseud_t pseud)
{
	if(!msk)
	{	prinft("error:null pointer passed to Free_user_pseud.\n");
		return;	
	};
	
	free(pseud);
	
	return;
}

void Free_user_keypair (user_keypair_t keypair)
{
	if(!msk)
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









