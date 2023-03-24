/*
 * brute forces a file open encrypted PDF key using a simple algorithm.
 * This works with the 2023 file open algorithm version 2 files using RC4.
 * The encryption password is a 5-letter string containing only A-Z and 0-9,
 * it is expanded by the objectid and genno.
 *
 * You might have to adjust the encryption parameters if file open changes
 * something or provided you with different sets of keys.
 *
 * Runtime on an 8th generation intel CPU core less than 2 minutes for the
 * complete keyspace.
 *
 * This program uses the first object with a minimum length and a FlateDecode
 * filter to verify the password using the inflate method, only accepting the
 * password when inflate exits without error.
 *
 * The implementation is a proof of concept and might not work on your PDF file.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/rc4.h>
#include <malloc.h>
#include <ctype.h>
#include <zlib.h>

/*
 * The memmem() function finds the start of the first occurrence of the
 * substring 'needle' of length 'nlen' in the memory area 'haystack' of
 * length 'hlen'.
 *
 * The return value is a pointer to the beginning of the sub-string, or
 * NULL if the substring is not found.
 */
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;

    if (!nlen)
        return NULL;

    needle_first = *(unsigned char *)needle;

    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;

        p++;
        plen = hlen - (p - haystack);
    }

    return NULL;
}


void md5_proxy(const unsigned char *d, size_t n, unsigned char *md) {
    MD5(d, n, md);
}

void decrypt(const char *password, unsigned int objid, unsigned int genno, const char* buffer, size_t len, char *target) {
    char key[32];
    char md5Result[32];
    RC4_KEY rc4key;
    int i = strlen(password);
    strncpy(key, password, 32);
    key[i] = objid;
    key[i+1] = objid >> 8;
    key[i+2] = objid >> 16;
    key[i+3] = genno;
    key[i+4] = genno >> 8;


    md5_proxy(key, i+5, md5Result);

    RC4_set_key(&rc4key, (i + 5) <= 16 ? (i + 5) : 16, md5Result);
    RC4(&rc4key, len, buffer, target);
}

#define CHUNK 16384
int unzip(const char* buffer, size_t len, char* target, size_t *targetLen)
{
    int ret;
    z_stream strm;
    
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = len;
    strm.next_in = buffer;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;
    
    strm.avail_out = *targetLen;
    strm.next_out = target;
    ret = inflate(&strm, Z_FINISH);
    (void)inflateEnd(&strm);
    if (ret == Z_OK || ret == Z_STREAM_END) {
        *targetLen = strm.total_out;
        return Z_OK;
    }
    return ret;
} 

int extract_object_id_before(const char *buffer, const char *offset) {
    const char *c = offset;
    int state = 0;
    unsigned int objid, genno;
    while (c > buffer) {
        switch(state) {
            case 0: /* init: search space */
                if (*c == ' ') state = 1;
                break;
            case 1: /* found space, search number */
                if (isdigit(*c)) state = 2;
                break;
            case 2: /* found first number, search space */
                if (*c == ' ') state = 3;
                break;
            case 3: /* found second space, search number */
                if (isdigit(*c)) state = 4;
                break;
            case 4: /* found second number, find beginning */
                if (!isdigit(*c)) {
                    int res = sscanf(c+1, "%u %u", &objid, &genno);
                    if(res == 2) {
                        return objid;
                    }
                    return -1;
                }
                break;
        }
        c--;
    }
    return -1;
}

const char* extract_stream(const char* buffer) {
    const char *begin = strstr(buffer, "stream") + 6;
    if(begin[0] == '\r' && begin[1] == '\n') {
        return begin + 2;
    }
    if(begin[0] == '\n') {
        return begin + 1;
    }
    return NULL;
}

int increment_password(char *str)
{
    int index, carry;
    int carry_count = 0;
    for(index = strlen(str)-1;index>=0;--index){
        if(str[index] == 'Z'){
            carry = 1;
            if(++carry_count == 4) {
                printf("Password: %s\n", str);
            }
            str[index] = '0';
        } else if(str[index] == '9'){
            carry = 0;
            str[index] = 'A';
        } else {
            carry = 0;
            str[index] += 1;
        }
        if(carry == 0) return 0;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char linebuf[65536];
    char *linebufend = linebuf+65536;
    char *pos = linebuf;
    char *unzipped;
    size_t unzippedLen;
    const char *buffer;
    size_t bufferLen;
    int objid;
    char *decrypted;
    int maxObjLen = 65536;
    
    int ret;
    if(argc < 2) {
        printf("Usage: %s <pdf file> [<max object length>]\n", argv[0]);
	printf("safe bet is to use a high number, e.g. 50000 for object length\n");
	printf("but if your PDF file has a small object in the first 64 kBytes, using that one\n");
	printf("will speed up the brute forcing a lot.\n");
        return -1;
    }
    if(argc == 3) {
	sscanf(argv[2], "%u", &maxObjLen);
    }
    
    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        exit(EXIT_FAILURE);
    }
    fread(linebuf, 65535, 1, fp);
    while(pos < linebufend) {
	/* ToDo: Support PDF files where the first suitable block is behind 4K */
        const char *search = "obj<</Filter/FlateDecode/Length";
        const char *objStr = memmem(pos, linebufend-pos, search, strlen(search));
	if (!objStr) {
	    printf("Did not find any further FlateDecode object in search buffer - buffer too short or PDF parser too simple? Try adjusting search string in code.\n");
	    return 1;
	}
        unsigned int objLength;
        int n = sscanf(objStr + strlen(search), " %u", &objLength);
	printf("n: %d, length: %u\n", n, objLength);
        if (n == 1 && objLength < maxObjLen) {
            objid = extract_object_id_before(pos, objStr);
            printf("Object: %u of length %u\n", objid, objLength);
            buffer = extract_stream(objStr + strlen(search));
            bufferLen = objLength;
            if(buffer != NULL && objid >= 0) {
		/* found satisfying stream */
                break;
            } else {
                printf("Parse error, looking for next object...\n");
	    }
        }
	pos = objStr + 1;
    }
    if (!buffer || objid < 0) {
	printf("Did not find suitable object - try manually inspecting your PDF and adjusting code a bit.\n");
	return 1;
    }
    printf("first buffer: %2X last buffer: %2X\n", buffer[0], buffer[bufferLen-1]);

    char *password = malloc(6);
    memcpy(password, "00000", 6);
    decrypted = malloc(bufferLen + 1);
    unzippedLen = CHUNK;
    unzipped = malloc(CHUNK);
    do {
        decrypt(password, objid, 0, buffer, bufferLen, decrypted);
        ret = unzip(decrypted, bufferLen, unzipped, &unzippedLen);
        
        if (ret == Z_OK) {
            printf("UNZIP (%s) ret %d len %u PW %s\n", argv[1], ret, unzippedLen, password);
            for(size_t i = 0; i < unzippedLen; i++)
                printf("%c", unzipped[i]);
        }
        if (increment_password(password)) {
            printf("Password not found, keyspace insufficient?\n");
            break;
        }

    } while (ret != Z_OK);
    
    return 0;
}
