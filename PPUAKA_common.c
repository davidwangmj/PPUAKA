/* Implementation of WANG-YAN PPUAKA scheme
 * Code by:  MINGJUN WANG   xdmjwang@hotmail.com
 *
 * PPUAKA_common.c
 */
#include "PPUAKA_common.h"

void
init_aes( element_t k, int enc, AES_KEY* key, unsigned char* iv )
{
  int key_len;
  unsigned char* key_buf;

  key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  if( enc )
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

  memset(iv, 0, 16);
}

/*!
 * AES 128bit CBC mode encryption
 *
 * @param pt			GByteArrary of plaintext
 * @param k				Sercet message from KP-ABE
 * @return				GByteArray of ciphertext
 */

GByteArray*
aes_128_cbc_encrypt( GByteArray* pt, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* ct;
  guint8 len[4];
  guint8 zero;

  init_aes(k, 1, &key, iv);



  /* stuff in real length (big endian) before padding */
  len[0] = (pt->len & 0xff000000)>>24;
  len[1] = (pt->len & 0xff0000)>>16;
  len[2] = (pt->len & 0xff00)>>8;
  len[3] = (pt->len & 0xff)>>0;
  g_byte_array_prepend(pt, len, 4);

  zero = 0;
  while( pt->len % 16 )
    g_byte_array_append(pt, &zero, 1);

  ct = g_byte_array_new();
  g_byte_array_set_size(ct, pt->len);

  AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);
  return ct;
}

/*!
 * AES 128bit CBC mode decryption
 *
 * @param pt			GByteArrary of ciphertext
 * @param k				Sercet message from KP-ABE
 * @return				GByteArray of plaintext
 */

GByteArray*
aes_128_cbc_decrypt( GByteArray* ct, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* pt;
  unsigned int len;

  init_aes(k, 0, &key, iv);

  pt = g_byte_array_new();
  g_byte_array_set_size(pt, ct->len);

  AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);



  /* get real length */
  len = 0;
  len = len
    | ((pt->data[0])<<24) | ((pt->data[1])<<16)
    | ((pt->data[2])<<8)  | ((pt->data[3])<<0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);

  /* truncate any garbage from the padding */
  g_byte_array_set_size(pt, len);

  return pt;
}

/*!
 * Open file with read mode or die
 *
 * @param file			File name
 * @return				File handler
 */

FILE*
fopen_read_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "r")) )
		die("can't read file: %s\n", file);

	return f;
}

/*!
 * Open file with write mode or die
 *
 * @param file			File name
 * @return				File handler
 */

FILE*
fopen_write_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "w")) )
		die("can't write file: %s\n", file);

	return f;
}

/*!
 * Open file and turn it into a GByteArray
 *
 * @param file			File name
 * @return				GByteArray
 */

GByteArray*
suck_file( char* file )
{
	FILE* f;
	GByteArray* a;
	struct stat s;

	a = g_byte_array_new();
	stat(file, &s);
	g_byte_array_set_size(a, s.st_size);

	f = fopen_read_or_die(file);
	fread(a->data, 1, s.st_size, f);
	fflush(f);
	fclose(f);

	return a;
}

/*!
 * Open file and turn it into a String
 *
 * @param file			File name
 * @return				String
 */

char*
suck_file_str( char* file )
{
	GByteArray* a;
	char* s;
	unsigned char zero;

	a = suck_file(file);
	zero = 0;
	g_byte_array_append(a, &zero, 1);
	s = (char*) a->data;
	g_byte_array_free(a, 0);

	return s;
}

/*!
 * Get input from stdin and turn it into a String
 *
 * @return				String
 */

char*
suck_stdin()
{
	GString* s;
	char* r;
	int c;

	s = g_string_new("");
	while( (c = fgetc(stdin)) != EOF )
		g_string_append_c(s, c);

	r = s->str;
	g_string_free(s, 0);

	return r;
}

/*!
 * Output GByteArray into a file, if free is one, free the GByteArray
 *
 * @param file			File name
 * @param b				GByteArray
 * @param free			Free flag
 * @return				None
 */

void
spit_file( char* file, GByteArray* b, int free )
{
	FILE* f;

	f = fopen_write_or_die(file);
	fwrite(b->data, 1, b->len, f);
	fclose(f);

	if( free )
		g_byte_array_free(b, 1);
}

/*!
 * Terminate program with error message
 *
 * @param fmt			Error message
 * @return				None
 */

void
die(char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
}

///////////////////////////////////////////////////////////////////////

/* data operation */

// serialize_uint32, unserialize_uint32, serialize_element,
// unserialize_element, serialize_string, unserialize_string
// those function serialize/unserialize the data structure.
void
serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

uint32_t
unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r;
}

void
serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

void
unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b->data + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

void
serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

//void new_serialize_string( GByteArray* b, char* s, int len)
//{
//
//	while(1)
//	{
//		g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
//		if((len - strlen(s) - 1)>0)
//		{
//			len = len-strlen(s)-1;
//			s = s + strlen(s)+1;
//			continue;
//		}
//		else if((len - strlen(s) - 1)==0)
//			break;
//		else
//			printf("error\n ");
//	}
//}


char*
unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
	if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

//char * new_unserialize_string( GByteArray* b, int* offset, int len )
//{
//	GString* s;
//	char* r;
//	char c;
//	int loop;
//
//	s = g_string_sized_new(32);
//	for(loop = 0; loop < len; loop ++)
//	{
//		c = b->data[(*offset)++];
//		g_string_append_c(s, c);
//	}
//
//	r = s->str;
//	g_string_free(s, 0);
//
//	return r;
//}

//serialize

GByteArray* PPUAKA_params_serialize( PPUAKA_params_t* params )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  params->pairing_desc);
	serialize_element(b, params->g);
	serialize_element(b, params->h);
	//serialize_element(b, params->q);
	serialize_element(b, params->g_hat_alpha);

	return b;
}

GByteArray* PPUAKA_msk_serialize( PPUAKA_msk_t* msk )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, msk->alpha);

	//test
	//PPUAKA_msk_free(msk);

	return b;
}

GByteArray* PPUAKA_keypair_serialize( PPUAKA_user_keypair_t* keypair )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, keypair->pub);
	serialize_element(b, keypair->prv);

	return b;
}

GByteArray* PPUAKA_realid_serialize( PPUAKA_user_realid_t* realid )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  realid->rid);

	return  b;

}


GByteArray* PPUAKA_pseud_serialize( PPUAKA_user_pseud_t* pseud )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  pseud->pid);
	serialize_string(b, pseud->timestamp);

	return  b;
}

GByteArray* PPUAKA_sessionid_serialize( PPUAKA_session_id_t* sessionid )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  sessionid->sid);

	return  b;
}

GByteArray* PPUAKA_hint_serialize( PPUAKA_user_hint_t* hint )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, hint->beta);
	serialize_element(b, hint->hint_first);
	return b;
}

GByteArray* PPUAKA_msg_serialize( PPUAKA_user_message_t* msg )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  msg->sid);
	serialize_string(b,  msg->pid);
	serialize_uint32(b, msg->index);		//can use unsigned int?
	serialize_element(b, msg->hint_first);
	return  b;
}

//void GByteArray_Modify()

GByteArray* PPUAKA_sign_serialize( PPUAKA_user_signature_t* sign )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, sign->u);
	serialize_element(b, sign->h);
	serialize_element(b, sign->v);
	return  b;
}

GByteArray* PPUAKA_key_material_serialize( PPUAKA_user_key_material_t* key_material )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, key_material->left_key);
	serialize_element(b, key_material->right_key);
	serialize_element(b, key_material->hint_plus);
	return  b;
}

GByteArray* PPUAKA_session_key_serialize( PPUAKA_session_key_t* session_key )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, session_key->ssk);

	return  b;
}


//unserialize

PPUAKA_params_t* PPUAKA_params_unserialize( GByteArray* b, int free )
{
	PPUAKA_params_t* params;
	int offset;

	params = (PPUAKA_params_t*) malloc(sizeof(PPUAKA_params_t));
	offset = 0;

	params->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(params->e, params->pairing_desc, strlen(params->pairing_desc));

	element_init_G1(params->g,          params->e);
	element_init_G2(params->h,         params->e);
	//element_init_G2(params->q,         params->e);
	element_init_GT(params->g_hat_alpha,    params->e);

	unserialize_element(b, &offset, params->g);
	unserialize_element(b, &offset, params->h);
	//unserialize_element(b, &offset, params->q);
	unserialize_element(b, &offset, params->g_hat_alpha);

	if( free )
		g_byte_array_free(b, 1);

	return params;
}

PPUAKA_msk_t* PPUAKA_msk_unserialize( PPUAKA_params_t* params, GByteArray* b, int free )
{
	PPUAKA_msk_t* msk;
	int offset;

	msk = (PPUAKA_msk_t*) malloc(sizeof(PPUAKA_msk_t));
	offset = 0;


	element_init_Zr(msk->alpha, params->e);

	unserialize_element(b, &offset, msk->alpha);
	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

PPUAKA_user_keypair_t* PPUAKA_keypair_unserialize( PPUAKA_params_t* params, GByteArray* b, int free )
{
	PPUAKA_user_keypair_t* keypair;
	int offset;

	keypair = (PPUAKA_user_keypair_t*) malloc(sizeof(PPUAKA_user_keypair_t));
	offset = 0;


	element_init_G1(keypair->pub, params->e);
	element_init_G1(keypair->prv, params->e);

	unserialize_element(b, &offset, keypair->pub);
	unserialize_element(b, &offset, keypair->prv);

	if( free )
		g_byte_array_free(b, 1);

	return keypair;
}

PPUAKA_user_realid_t* PPUAKA_realid_unserialize(GByteArray* b, int free )
{
	PPUAKA_user_realid_t* realid;

	int offset;

	realid = (PPUAKA_user_realid_t*) malloc(sizeof(PPUAKA_user_realid_t));
	offset = 0;

	realid->rid = unserialize_string(b, &offset);

	if( free )
		g_byte_array_free(b, 1);

	return realid;

}
PPUAKA_user_pseud_t* PPUAKA_pseud_unserialize(GByteArray* b, int free )
{

	PPUAKA_user_pseud_t* pseud;

	int offset;

	pseud = (PPUAKA_user_pseud_t*) malloc(sizeof(PPUAKA_user_pseud_t));
	offset = 0;

	pseud->pid = unserialize_string(b, &offset);
	pseud->timestamp = unserialize_string(b, &offset);

	if( free )
		g_byte_array_free(b, 1);

	return pseud;

}

PPUAKA_session_id_t* PPUAKA_sessionid_unserialize(GByteArray* b, int free )
{
	PPUAKA_session_id_t* sessionid;

	int offset;

	sessionid = (PPUAKA_session_id_t*) malloc(sizeof(PPUAKA_session_id_t));
	offset = 0;

	sessionid->sid = unserialize_string(b, &offset);

	if( free )
		g_byte_array_free(b, 1);

	return sessionid;

}

PPUAKA_user_hint_t* PPUAKA_hint_unserialize(PPUAKA_params_t* params, GByteArray* b, int free )
{

	PPUAKA_user_hint_t* hint;

	int offset;

	hint = (PPUAKA_user_hint_t*) malloc(sizeof(PPUAKA_user_hint_t));
	offset = 0;


	element_init_Zr(hint->beta, params->e);
	element_init_G1(hint->hint_first, params->e);

	unserialize_element(b, &offset, hint->beta);
	unserialize_element(b, &offset, hint->hint_first);

	if( free )
		g_byte_array_free(b, 1);

	return hint;

}
PPUAKA_user_message_t* PPUAKA_msg_unserialize(PPUAKA_params_t* params, GByteArray* b, int free )
{
	PPUAKA_user_message_t* msg;

	int offset;

	msg = (PPUAKA_user_message_t*) malloc(sizeof(PPUAKA_user_message_t));
	offset = 0;

	element_init_G1(msg->hint_first, params->e);

	msg->sid = unserialize_string(b, &offset);
	msg->pid = unserialize_string(b, &offset);
	msg->index = unserialize_uint32 (b, &offset);
	unserialize_element(b, &offset, msg->hint_first);

	if( free )
		g_byte_array_free(b, 1);

	return msg;

}

PPUAKA_user_signature_t* PPUAKA_sign_unserialize(PPUAKA_params_t* params, GByteArray* b, int free )
{

	PPUAKA_user_signature_t* sign;

	int offset;

	sign = (PPUAKA_user_signature_t*) malloc(sizeof(PPUAKA_user_signature_t));
	offset = 0;


	element_init_G1(sign->u, params->e);
	element_init_G1(sign->h, params->e);
	element_init_G1(sign->v, params->e);

	unserialize_element(b, &offset, sign->u);
	unserialize_element(b, &offset, sign->h);
	unserialize_element(b, &offset, sign->v);

	if( free )
		g_byte_array_free(b, 1);

	return sign;
}

PPUAKA_user_key_material_t* PPUAKA_key_material_unserialize(PPUAKA_params_t* params, GByteArray* b, int free )
{
	PPUAKA_user_key_material_t* key_material;

	int offset;

	key_material = (PPUAKA_user_key_material_t*) malloc (sizeof (PPUAKA_user_key_material_t));

	offset = 0;

	element_init_G1(key_material->left_key, params->e);
	element_init_G1(key_material->right_key, params->e);
	element_init_G1(key_material->hint_plus, params->e);

	unserialize_element(b, &offset, key_material->left_key);
	unserialize_element(b, &offset, key_material->right_key);
	unserialize_element(b, &offset, key_material->hint_plus);

	if( free )
		g_byte_array_free(b, 1);

	return key_material;

}

PPUAKA_session_key_t* PPUAKA_session_key_unserialize(PPUAKA_params_t* params, GByteArray* b, int free )
{
	PPUAKA_session_key_t* session_key;

	int offset;

	session_key = (PPUAKA_session_key_t*) malloc (sizeof (PPUAKA_session_key_t));

	offset = 0;

	element_init_G1(session_key->ssk, params->e);


	unserialize_element(b, &offset, session_key->ssk);


	if( free )
		g_byte_array_free(b, 1);

	return session_key;

}

//free

void PPUAKA_params_free( PPUAKA_params_t* params )
{

	element_clear(params->g);
	element_clear(params->h);
	//element_clear(params->q);
	element_clear(params->g_hat_alpha);
	pairing_clear(params->e);
	free(params->pairing_desc);
	free(params);
}

void PPUAKA_msk_free( PPUAKA_msk_t* msk)
{
	element_clear(msk->alpha);
	free(msk);
}

void PPUAKA_keypair_free( PPUAKA_user_keypair_t* keypair)
{
	element_clear(keypair->pub);
	element_clear(keypair->prv);
	free(keypair);
}

void PPUAKA_realid_free( PPUAKA_user_realid_t* realid )
{
	free(realid->rid);
	free(realid);
}

void PPUAKA_pseud_free( PPUAKA_user_pseud_t* pseud )
{
	free(pseud->pid);
	free(pseud->timestamp);
	free(pseud);
}

void PPUAKA_sessionid_free( PPUAKA_session_id_t* sessionid )
{
	free(sessionid->sid);
	free(sessionid);
}

void PPUAKA_hint_free( PPUAKA_user_hint_t* hint )
{
	element_clear(hint->beta);
	element_clear(hint->hint_first);
	free(hint);
}

void PPUAKA_msg_free( PPUAKA_user_message_t* msg )
{
	free(msg->sid);
	free(msg->pid);
	element_clear(msg->hint_first);

}

void PPUAKA_sign_free( PPUAKA_user_signature_t* sign )
{
	element_clear(sign->u);
	element_clear(sign->h);
	element_clear(sign->v);
}

void PPUAKA_key_material_free( PPUAKA_user_key_material_t* key_material )
{
	element_clear(key_material->left_key);
	element_clear(key_material->right_key);
	element_clear(key_material->hint_plus);
}

void PPUAKA_session_key_free( PPUAKA_session_key_t* session_key )
{
	element_clear(session_key->ssk);
}
