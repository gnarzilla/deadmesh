#ifndef DEADLIGHT_SMTP_H
#define DEADLIGHT_SMTP_H

#include "../core/deadlight.h"

#ifdef __cplusplus
extern "C" {
#endif

// Register the SMTP protocol handler with the core system
void deadlight_register_smtp_handler(void);

gboolean smtp_send_message(const gchar *from, const gchar *to, 
                          const gchar *subject, const gchar *body,
                          GError **error);

// SMTP-specific data structures
typedef struct {
    gchar *sender;
    gchar *recipient;
    gboolean in_data_mode;
    GByteArray *message_buffer;
    gboolean should_forward_to_api;
} DeadlightSMTPData;

#ifdef __cplusplus
}
#endif

#endif // DEADLIGHT_SMTP_H
