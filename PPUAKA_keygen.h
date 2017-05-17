/*
 * PPUAKA_keygen.h
 *
 *  Created on: 2017-4-23
 *      Author: MJWang
 */

#ifndef PPUAKA_KEYGEN_H_
#define PPUAKA_KEYGEN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <pbc_test.h>


#include "PPUAKA_lib.h"
#include "PPUAKA_common.h"
#include "PPUAKA_core.h"

void ppuaka_keygen(	char* params_file,
					char* keypair_file,
					char* key_material_file,
					char** msg_2_keygen_file,
					char** sign_2_keygen_file,
					char* session_key_file,
					int UserNum
					);



#endif /* PPUAKA_KEYGEN_H_ */
