#ifndef LAB_C5_MODULE_LOADER_H
#define LAB_C5_MODULE_LOADER_H

#include "module_api.h"
#include <furi.h>
#include <flipper_application/plugins/plugin_manager.h>

#define C5_MODULE_LINE_CAPACITY 192u

typedef struct {
    FuriMutex* lock;
    PluginManager* manager;
    const C5ModuleV3* module;
    void* state;
    C5HostApiV3 host;
    char line[C5_MODULE_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
    C5TextInputRequest text_input;
    bool text_input_pending;
    bool text_input_active;
    uint32_t generation;
} C5ModuleRuntime;

typedef enum {
    C5ModuleLoadOk = 0,
    C5ModuleLoadNoMemory,
    C5ModuleLoadManagerError,
    C5ModuleLoadBadApi,
    C5ModuleLoadEnterError,
} C5ModuleLoadResult;

bool c5_module_runtime_init(C5ModuleRuntime* runtime, const C5HostApiV3* host);
void c5_module_runtime_deinit(C5ModuleRuntime* runtime);
C5ModuleLoadResult c5_module_runtime_load(
    C5ModuleRuntime* runtime,
    const char* path,
    const void* params,
    size_t params_size);
void c5_module_runtime_unload(C5ModuleRuntime* runtime);
bool c5_module_runtime_active(C5ModuleRuntime* runtime);
void c5_module_runtime_feed(C5ModuleRuntime* runtime, const uint8_t* bytes, size_t length);
bool c5_module_runtime_draw(C5ModuleRuntime* runtime, Canvas* canvas);
C5InputResult c5_module_runtime_input(C5ModuleRuntime* runtime, const InputEvent* event);
void c5_module_runtime_tick(C5ModuleRuntime* runtime, uint32_t now_ticks);
bool c5_module_runtime_request_text_input(
    C5ModuleRuntime* runtime,
    const C5TextInputRequest* request);
bool c5_module_runtime_take_text_input(
    C5ModuleRuntime* runtime,
    C5TextInputRequest* request,
    uint32_t* generation);
bool c5_module_runtime_complete_text_input(
    C5ModuleRuntime* runtime,
    uint32_t generation,
    bool accepted,
    const char* text,
    size_t length);

#endif
