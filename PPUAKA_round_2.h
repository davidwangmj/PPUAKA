/*
 * PPUAKA_round_2.h
 *
 *  Created on: 2017-4-22
 *      Author: MJWang
 */

#ifndef PPUAKA_ROUND_2_H_
#define PPUAKA_ROUND_2_H_

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

void ppuaka_round_2(char* params_file,
					char* pseud_file,
					char* keypair_file,
					char* hint_1_file,
					char* msg_left_file,
					char* msg_right_file,
					char* sign_left_file,
					char* sign_right_file,
					char* key_material_file,
					char* msg_2_file,
					char* sign_2_file);

#endif /* PPUAKA_ROUND_2_H_ */
