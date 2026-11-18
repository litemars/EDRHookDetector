#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/* Hash the complete object referred to by fd without changing its offset. */
int sha256_fd(int fd, char hex[65]);
void sha256_bytes(const void *data, size_t len, char hex[65]);

#endif
