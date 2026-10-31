#pragma once

#include <stdint.h>

typedef struct PluginManager PluginManager;
typedef struct ElfApiInterface ElfApiInterface;

typedef enum {
    PluginManagerErrorNone = 0,
    PluginManagerErrorLoaderError,
    PluginManagerErrorApplicationIdMismatch,
    PluginManagerErrorAPIVersionMismatch,
} PluginManagerError;

PluginManager* plugin_manager_alloc(
    const char* application_id,
    uint32_t api_version,
    const ElfApiInterface* api_interface);
void plugin_manager_free(PluginManager* manager);
PluginManagerError plugin_manager_load_single(PluginManager* manager, const char* path);
const void* plugin_manager_get_ep(PluginManager* manager, uint32_t index);
