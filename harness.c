/* libmodbus server-side harness (modbus_reply)
 *
 * REQ_CAP selects the threat model:
 *   -DREQ_CAP=260   network-reachable model (the most modbus_receive can hand over)
 *   -DREQ_CAP=1024  API-contract model (caller supplies req_length directly)
 * Build both binaries and compare them; that comparison is the point of this
 * harness.
 */
#include <modbus.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef REQ_CAP
#define REQ_CAP 260
#endif

static modbus_t *ctx = NULL;
static modbus_mapping_t *mapping = NULL;

static void init_once(void)
{
    int sv[2];

    if (ctx != NULL)
        return;

    ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (ctx == NULL)
        exit(1);

    /* Required. Since 3.1.x the flush path in response_exception() sleeps for
     * the response timeout, which defaults to 500 ms. Without this line the
     * harness runs at 2-3 execs/sec because most inputs take an exception
     * branch. 3.0.x takes a struct timeval, hence the version split. */
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

    /* A nonblocking socketpair rather than /dev/null: send() does not fail
     * immediately with ENOTSOCK, so send_msg / send_msg_pre stay covered.
     * Nothing ever drains it, so writes just return EAGAIN. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        exit(1);
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    modbus_set_socket(ctx, sv[0]);

    mapping = modbus_mapping_new(500, 500, 500, 500);
    if (mapping == NULL)
        exit(1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t req[REQ_CAP];

    if (size == 0 || size > REQ_CAP)
        return 0;

    init_once();

    /* Without the memset, req[size..REQ_CAP-1] keeps stale bytes from the
     * previous iteration and results stop being reproducible. */
    memset(req, 0, sizeof req);
    memcpy(req, data, size);

    modbus_reply(ctx, req, (int) size, mapping);
    return 0;
}
