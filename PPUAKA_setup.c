/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_setup.c
 */

/*
	Generate system parameters, a public key, a master secret key,
	and a hash function.
 */

#include "PPUAKA_setup.h"

void ppukak_setup()
{
	char* params_file = "params_key";
	char* msk_file = "msk_key";
	PPUAKA_params_t* params;
	PPUAKA_msk_t* msk;

	setup(&params, &msk);

	spit_file(params_file,PPUAKA_params_serialize(params),1);
	spit_file(msk_file,PPUAKA_msk_serialize(msk),1);
}
