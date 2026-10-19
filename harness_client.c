/* libmodbus client-side harness — response parsing paths
 *
 * Two things matter here:
 *  1) The request type is dispatched from the input, so the harness covers the
 *     whole response parser instead of only FC 0x01.
 *  2) Destination buffers are malloc'd at exactly the requested size, so ASan
 *     heap redzones catch out-of-bounds writes. Heap redzones work even when
 *     the library itself is not instrumented, which makes this the most robust
 *     detector in the setup.
 */
#include <modbus.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

static modbus_t *ctx = NULL;

static void init_once(void)
{
    if (ctx != NULL)
        return;
    ctx = modbus_new_tcp("127.0.0.1", 1502);
    if (ctx == NULL)
        exit(1);
    modbus_set_slave(ctx, 1);
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
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int sv[2];
    uint8_t op;
    uint16_t nb;
    uint8_t *bits;
    uint16_t *regs;

    if (size < 3 || size > 600)
        return 0;

    init_once();

    op = data[0] % 9;
    nb = (uint16_t) (data[1] % 125) + 1; /* the requested count is fuzzed too */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return 0;
    if (write(sv[1], data + 2, size - 2) < 0) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    shutdown(sv[1], SHUT_WR);
    modbus_set_socket(ctx, sv[0]);

    /* Allocate exactly what was requested. Never oversize these buffers — an
     * oversized destination hides the overflow you are looking for. */
    bits = calloc(nb, sizeof(uint8_t));
    regs = calloc(nb, sizeof(uint16_t));
    if (bits == NULL || regs == NULL) {
        free(bits);
        free(regs);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }

    switch (op) {
    case 0: modbus_read_bits(ctx, 0, nb, bits); break;
    case 1: modbus_read_input_bits(ctx, 0, nb, bits); break;
    case 2: modbus_read_registers(ctx, 0, nb, regs); break;
    case 3: modbus_read_input_registers(ctx, 0, nb, regs); break;
    case 4: modbus_write_bit(ctx, 0, 1); break;
    case 5: modbus_write_register(ctx, 0, 0x1234); break;
    case 6: modbus_write_bits(ctx, 0, nb, bits); break;
    case 7: modbus_write_registers(ctx, 0, nb, regs); break;
    case 8: modbus_write_and_read_registers(ctx, 0, nb, regs, 0, nb, regs); break;
    default: break;
    }

    free(bits);
    free(regs);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
