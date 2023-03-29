#include <pbc/pbc.h>
#include <pbc/pbc_field.h>
#include <pbc/pbc_test.h>
#include <glib.h>
#define NUM_ATTR_BITS 32

GByteArray* suck_file( char* file );
// void        spit_file( char* file, GByteArray* b );
void element_from_string( element_t h, char* s );
FILE* fopen_read_or_die( char* file );
FILE* fopen_write_or_die( char* file );
char* suck_file_str( char* file );
char* suck_stdin();
void die(char* fmt, ...);

// GByteArray* aes_128_cbc_encrypt( GByteArray* pt, element_t k );
// GByteArray* aes_128_cbc_decrypt( GByteArray* ct, element_t k );