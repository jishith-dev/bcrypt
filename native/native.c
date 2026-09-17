
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "crypt_blowfish.h"
#include "crypt_gensalt.h"

#define BCRYPT_HASH_SIZE 128
#define BCRYPT_SALT_SIZE 16
#define BCRYPT_MIN_COST 4
#define BCRYPT_MAX_COST 31
#define BCRYPT_HASH_LENGTH 60


/*
 * Secure random byte generation.
 *
 * Returns:
 *   1 on success
 *   0 on failure
 */
static int zen_secure_random(
    unsigned char *buffer,
    size_t size
) {
    if (buffer == NULL || size == 0) {
        return 0;
    }

    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        return 0;
    }

    size_t offset = 0;

    while (offset < size) {
        ssize_t result = read(
            fd,
            buffer + offset,
            size - offset
        );

        if (result > 0) {
            offset += (size_t)result;
            continue;
        }

        if (result < 0 && errno == EINTR) {
            continue;
        }

        close(fd);
        return 0;
    }

    close(fd);
    return 1;
}


static int zen_valid_cost(int cost) {
    return cost >= BCRYPT_MIN_COST &&
           cost <= BCRYPT_MAX_COST;
}


/*
 * Validate a bcrypt hash.
 *
 * Openwall supports the standard bcrypt prefixes:
 *   $2a$
 *   $2b$
 *   $2y$
 */
static int zen_valid_hash(const char *hash) {
    if (hash == NULL) {
        return 0;
    }

    if (strlen(hash) != BCRYPT_HASH_LENGTH) {
        return 0;
    }

    if (hash[0] != '$' ||
        hash[1] != '2' ||
        hash[3] != '$' ||
        hash[6] != '$') {
        return 0;
    }

    if (hash[2] != 'a' &&
        hash[2] != 'b' &&
        hash[2] != 'y') {
        return 0;
    }

    if (hash[4] < '0' ||
        hash[4] > '9' ||
        hash[5] < '0' ||
        hash[5] > '9') {
        return 0;
    }

    return 1;
}


char *zen_bcrypt_hash(
    const char *password,
    int cost
) {
    if (password == NULL) {
        return NULL;
    }

    if (!zen_valid_cost(cost)) {
        return NULL;
    }

    unsigned char random_bytes[BCRYPT_SALT_SIZE];

    if (!zen_secure_random(
        random_bytes,
        sizeof(random_bytes)
    )) {
        return NULL;
    }

    char setting[64];

    char *generated_setting =
        _crypt_gensalt_blowfish_rn(
            "$2b$",
            (unsigned long)cost,
            (const char *)random_bytes,
            sizeof(random_bytes),
            setting,
            sizeof(setting)
        );

    if (generated_setting == NULL) {
        return NULL;
    }

    char *output = malloc(BCRYPT_HASH_SIZE);

    if (output == NULL) {
        return NULL;
    }

    char *result = _crypt_blowfish_rn(
        password,
        setting,
        output,
        BCRYPT_HASH_SIZE
    );

    if (result == NULL) {
        free(output);
        return NULL;
    }

    /*
     * Reject unexpected output.
     */
    if (strlen(output) != BCRYPT_HASH_LENGTH) {
        free(output);
        return NULL;
    }

    return output;
}


/*
 * Constant-time byte comparison.
 *
 * Returns:
 *   1 if equal
 *   0 if different
 */
static int zen_constant_time_equal(
    const char *a,
    const char *b,
    size_t length
) {
    unsigned char difference = 0;

    for (size_t i = 0; i < length; i++) {
        difference |= (unsigned char)(
            a[i] ^ b[i]
        );
    }

    return difference == 0;
}


/*
 * Verify a password against a bcrypt hash.
 *
 * Returns:
 *   1 = valid password
 *   0 = invalid password or malformed hash
 */
int zen_bcrypt_verify(
    const char *password,
    const char *hash
) {
    if (password == NULL || hash == NULL) {
        return 0;
    }

    if (!zen_valid_hash(hash)) {
        return 0;
    }

    char output[BCRYPT_HASH_SIZE];

    char *result = _crypt_blowfish_rn(
        password,
        hash,
        output,
        sizeof(output)
    );

    if (result == NULL) {
        return 0;
    }

    if (strlen(output) != BCRYPT_HASH_LENGTH) {
        return 0;
    }

    return zen_constant_time_equal(
        output,
        hash,
        BCRYPT_HASH_LENGTH
    );
}

