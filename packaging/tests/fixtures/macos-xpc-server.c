#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <xpc/xpc.h>

static SecRequirementRef requirement;
static const char *counter_path;

static void record_acceptance(void) {
    int descriptor = open(counter_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (descriptor < 0) {
        _exit(70);
    }
    if (write(descriptor, "1\n", 2) != 2) {
        _exit(70);
    }
    close(descriptor);
}

static void handle_peer(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
      if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
          return;
      }
      SecCodeRef sender = NULL;
      OSStatus status = SecCodeCreateWithXPCMessage(event, kSecCSDefaultFlags, &sender);
      if (status == errSecSuccess) {
          status = SecCodeCheckValidity(sender, kSecCSStrictValidate, requirement);
      }
      if (sender != NULL) {
          CFRelease(sender);
      }
      bool allowed = status == errSecSuccess;
      if (allowed) {
          record_acceptance();
      }
      xpc_object_t reply = xpc_dictionary_create_reply(event);
      if (reply != NULL) {
          xpc_dictionary_set_bool(reply, "allowed", allowed);
          xpc_connection_send_message(peer, reply);
      }
    });
    xpc_connection_resume(peer);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        return 64;
    }
    counter_path = argv[3];
    CFStringRef requirement_text = CFStringCreateWithCString(
        kCFAllocatorDefault, argv[2], kCFStringEncodingUTF8);
    if (requirement_text == NULL ||
        SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags, &requirement) !=
            errSecSuccess) {
        return 65;
    }
    CFRelease(requirement_text);

    xpc_connection_t listener = xpc_connection_create_mach_service(
        argv[1], dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (listener == NULL) {
        return 69;
    }
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
      if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
          handle_peer((xpc_connection_t)event);
      }
    });
    xpc_connection_resume(listener);
    dispatch_main();
}
