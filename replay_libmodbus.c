/* replay_libmodbus.c — behavioral replay driver, not a fuzzer.
 *
 * Reads one raw Modbus TCP ADU per invocation, passes it to
 * modbus_reply, and classifies what the library did with it. Prints one
 * TSV line:  <class>\t<detail>
 *
 * Classes
 *   ACCEPT     a normal response was produced
 *   EXCEPTION  the server answered with an exception PDU (fc | 0x80)
 *   DROP       no response was written and no error was signalled
 *   ERROR      modbus_reply returned -1
 *   (CRASH is observed by the runner from the exit status, not here)
 *
 * Build twice, as with the fuzzing harness:
 *   -DREQ_CAP=260   network-reachable model
 *   -DREQ_CAP=1024  API contract model
 *
 * This driver deliberately does NOT share code with harness.c. It reads
 * raw ADUs so that the pymodbus driver can be given byte-identical
 * input.
 */
#include <modbus.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef REQ_CAP
#define REQ_CAP 260
#endif

#define TCP_HEADER_LENGTH 7

int main(int argc, char **argv)
{
    FILE *f;
    uint8_t req[REQ_CAP];
    uint8_t rsp[512];
    size_t len;
    int sv[2], rc, saved_errno;
    ssize_t n;
    modbus_t *ctx;
    modbus_mapping_t *mapping;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <adu-file>\n", argv[0]);
        return 2;
    }

    f = fopen(argv[1], "rb");
    if (f == NULL) {
        printf("ERROR\tcannot open %s\n", argv[1]);
        return 2;
    }
    memset(req, 0, sizeof req);
    len = fread(req, 1, sizeof req, f);
    fclose(f);

    if (len == 0) {
        printf("SKIP\tempty file\n");
        return 0;
    }

    ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (ctx == NULL) {
        printf("ERROR\tmodbus_new_tcp failed\n");
        return 2;
    }

#if LIBMODBUS_VERSION_CHECK(3, 1, 0)
    modbus_set_response_timeout(ctx, 0, 1);
#else
    {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 1;
        modbus_set_response_timeout(ctx, &tv);
    }
#endif

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("ERROR\tsocketpair failed\n");
        return 2;
    }
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    modbus_set_socket(ctx, sv[0]);

    mapping = modbus_mapping_new(500, 500, 500, 500);
    if (mapping == NULL) {
        printf("ERROR\tmodbus_mapping_new failed\n");
        return 2;
    }

    errno = 0;
    rc = modbus_reply(ctx, req, (int) len, mapping);
    /* Save errno immediately. The read() below is on an empty nonblocking
     * socket and fails with EAGAIN, which would otherwise overwrite the
     * errno modbus_reply set. */
    saved_errno = errno;

    /* Read back whatever the library wrote to the socket. */
    n = read(sv[1], rsp, sizeof rsp);

    if (rc == -1) {
        printf("ERROR\trc=-1 errno=%d (%s)\n",
               saved_errno, modbus_strerror(saved_errno));
    } else if (n <= 0) {
        printf("DROP\trc=%d no response written\n", rc);
    } else if (n > TCP_HEADER_LENGTH && (rsp[TCP_HEADER_LENGTH] & 0x80)) {
        int ecode = (n > TCP_HEADER_LENGTH + 1) ? rsp[TCP_HEADER_LENGTH + 1] : -1;
        printf("EXCEPTION\tfc=0x%02x code=%d\n",
               rsp[TCP_HEADER_LENGTH] & 0x7F, ecode);
    } else {
        printf("ACCEPT\trc=%d rsp_bytes=%zd\n", rc, n);
    }

    modbus_mapping_free(mapping);
    close(sv[0]);
    close(sv[1]);
    modbus_free(ctx);
    return 0;
}
