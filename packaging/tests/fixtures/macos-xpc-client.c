#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <xpc/xpc.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        return 64;
    }
    char *end = NULL;
    long message_count = strtol(argv[2], &end, 10);
    if (end == argv[2] || *end != '\0' || message_count < 1 || message_count > 10) {
        return 64;
    }
    xpc_connection_t connection = xpc_connection_create_mach_service(argv[1], NULL, 0);
    if (connection == NULL) {
        return 69;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
      (void)event;
    });
    xpc_connection_resume(connection);
    for (long index = 0; index < message_count; index++) {
        xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_uint64(message, "sequence", (uint64_t)index);
        __block xpc_object_t reply = NULL;
        dispatch_semaphore_t completed = dispatch_semaphore_create(0);
        xpc_connection_send_message_with_reply(
            connection,
            message,
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
            ^(xpc_object_t value) {
              reply = xpc_retain(value);
              dispatch_semaphore_signal(completed);
            });
        if (dispatch_semaphore_wait(
                completed, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
            xpc_connection_cancel(connection);
            return 75;
        }
        if (xpc_get_type(reply) == XPC_TYPE_ERROR ||
            !xpc_dictionary_get_bool(reply, "allowed")) {
            xpc_release(reply);
            return 77;
        }
        xpc_release(reply);
    }
    return 0;
}
