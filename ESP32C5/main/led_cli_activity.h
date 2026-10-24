#ifndef JANOS_LED_CLI_ACTIVITY_H
#define JANOS_LED_CLI_ACTIVITY_H

#include "led_status_core.h"

/* Classify a CLI command's first argument. IDLE means no scoped LED action. */
led_status_activity_t led_cli_activity(const char *command, const char *subcommand);

#endif
