#include "module_loader.h"
#include "secure_clear.h"

#include <loader/firmware_api/firmware_api.h>
#include <string.h>

bool c5_module_runtime_init(C5ModuleRuntime* runtime, const C5HostApiV3* host) {
    if(!runtime || !host || host->version != C5_MODULE_API_VERSION ||
       host->size != sizeof(C5HostApiV3)) {
        return false;
    }
    memset(runtime, 0, sizeof(*runtime));
    runtime->lock = furi_mutex_alloc(FuriMutexTypeRecursive);
    if(!runtime->lock) return false;
    runtime->host = *host;
    return true;
}

void c5_module_runtime_unload(C5ModuleRuntime* runtime) {
    if(!runtime || !runtime->lock) return;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    PluginManager* manager = runtime->manager;
    const C5ModuleV3* module = runtime->module;
    void* state = runtime->state;
    runtime->manager = NULL;
    runtime->module = NULL;
    runtime->state = NULL;
    runtime->line_length = 0;
    runtime->discard_line = false;
    c5_secure_clear(runtime->line, sizeof(runtime->line));
    c5_secure_clear(&runtime->text_input, sizeof(runtime->text_input));
    runtime->text_input_pending = false;
    runtime->text_input_active = false;
    runtime->generation++;
    furi_mutex_release(runtime->lock);
    /* Callbacks are detached before leave. Do not hold the runtime lock while
       the module uses host services such as UART, which take their own mutex. */
    if(module && state && module->leave) module->leave(state, &runtime->host);
    if(manager) plugin_manager_free(manager);
}

void c5_module_runtime_deinit(C5ModuleRuntime* runtime) {
    if(!runtime || !runtime->lock) return;
    c5_module_runtime_unload(runtime);
    furi_mutex_free(runtime->lock);
    runtime->lock = NULL;
}

C5ModuleLoadResult c5_module_runtime_load(
    C5ModuleRuntime* runtime,
    const char* path,
    const void* params,
    size_t params_size) {
    if(!runtime || !runtime->lock || !path || !path[0] || (!!params != !!params_size)) {
        return C5ModuleLoadBadApi;
    }
    c5_module_runtime_unload(runtime);

    PluginManager* manager = plugin_manager_alloc(
        C5_MODULE_APP_ID, C5_MODULE_API_VERSION, firmware_api_interface);
    if(!manager) return C5ModuleLoadNoMemory;
    if(plugin_manager_load_single(manager, path) != PluginManagerErrorNone) {
        plugin_manager_free(manager);
        return C5ModuleLoadManagerError;
    }

    const C5ModuleV3* module = plugin_manager_get_ep(manager, 0);
    if(!module || module->version != C5_MODULE_API_VERSION ||
       module->size != sizeof(C5ModuleV3) || !module->enter || !module->leave ||
       (!module->on_line && !module->on_bytes) || !module->on_input || !module->draw) {
        plugin_manager_free(manager);
        return C5ModuleLoadBadApi;
    }

    void* state = module->enter(&runtime->host, params, params_size);
    if(!state) {
        plugin_manager_free(manager);
        return C5ModuleLoadEnterError;
    }

    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    runtime->manager = manager;
    runtime->module = module;
    runtime->state = state;
    runtime->line_length = 0;
    runtime->discard_line = false;
    runtime->text_input_pending = false;
    runtime->text_input_active = false;
    runtime->generation++;
    furi_mutex_release(runtime->lock);
    return C5ModuleLoadOk;
}

bool c5_module_runtime_active(C5ModuleRuntime* runtime) {
    if(!runtime || !runtime->lock) return false;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    bool active = runtime->module && runtime->state;
    furi_mutex_release(runtime->lock);
    return active;
}

void c5_module_runtime_feed(C5ModuleRuntime* runtime, const uint8_t* bytes, size_t length) {
    if(!runtime || !runtime->lock || !bytes || !length) return;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    if(runtime->module && runtime->state) {
        if(runtime->module->on_bytes) {
            runtime->module->on_bytes(runtime->state, &runtime->host, bytes, length);
        } else {
            for(size_t i = 0; i < length; i++) {
                char ch = (char)bytes[i];
                if(ch == '\r') continue;
                if(ch == '\n') {
                    if(!runtime->discard_line && runtime->line_length) {
                        runtime->line[runtime->line_length] = '\0';
                        runtime->module->on_line(runtime->state, &runtime->host, runtime->line);
                    }
                    c5_secure_clear(runtime->line, sizeof(runtime->line));
                    runtime->line_length = 0;
                    runtime->discard_line = false;
                } else if(!runtime->discard_line) {
                    if(runtime->line_length + 1 < sizeof(runtime->line)) {
                        runtime->line[runtime->line_length++] = ch;
                    } else {
                        runtime->line_length = 0;
                        runtime->discard_line = true;
                    }
                }
            }
        }
    }
    furi_mutex_release(runtime->lock);
}

bool c5_module_runtime_draw(C5ModuleRuntime* runtime, Canvas* canvas) {
    if(!runtime || !runtime->lock || !canvas) return false;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    bool handled = runtime->module && runtime->state;
    if(handled) runtime->module->draw(runtime->state, &runtime->host, canvas);
    furi_mutex_release(runtime->lock);
    return handled;
}

C5InputResult c5_module_runtime_input(C5ModuleRuntime* runtime, const InputEvent* event) {
    if(!runtime || !runtime->lock || !event) return C5InputIgnored;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    C5InputResult result = C5InputIgnored;
    if(runtime->module && runtime->state) {
        result = runtime->module->on_input(runtime->state, &runtime->host, event);
    }
    furi_mutex_release(runtime->lock);
    return result;
}

void c5_module_runtime_tick(C5ModuleRuntime* runtime, uint32_t now_ticks) {
    if(!runtime || !runtime->lock) return;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    if(runtime->module && runtime->state && runtime->module->tick) {
        runtime->module->tick(runtime->state, &runtime->host, now_ticks);
    }
    furi_mutex_release(runtime->lock);
}

bool c5_module_runtime_request_text_input(
    C5ModuleRuntime* runtime,
    const C5TextInputRequest* request) {
    if(!runtime || !runtime->lock || !request ||
       request->capacity < 2 || request->capacity > C5_TEXT_INPUT_VALUE_CAPACITY ||
       request->minimum_length >= request->capacity ||
       !memchr(request->header, '\0', sizeof(request->header)) ||
       !memchr(request->initial, '\0', request->capacity)) {
        return false;
    }

    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    bool accepted = runtime->module && runtime->state && runtime->module->on_text_input &&
                    !runtime->text_input_pending && !runtime->text_input_active;
    if(accepted) {
        runtime->text_input = *request;
        runtime->text_input_pending = true;
    }
    furi_mutex_release(runtime->lock);
    return accepted;
}

bool c5_module_runtime_take_text_input(
    C5ModuleRuntime* runtime,
    C5TextInputRequest* request,
    uint32_t* generation) {
    if(!runtime || !runtime->lock || !request || !generation) return false;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    bool ready = runtime->text_input_pending && runtime->module && runtime->state;
    if(ready) {
        *request = runtime->text_input;
        *generation = runtime->generation;
        runtime->text_input_pending = false;
        runtime->text_input_active = true;
    }
    furi_mutex_release(runtime->lock);
    return ready;
}

bool c5_module_runtime_complete_text_input(
    C5ModuleRuntime* runtime,
    uint32_t generation,
    bool accepted,
    const char* text,
    size_t length) {
    if(!runtime || !runtime->lock) return false;
    furi_mutex_acquire(runtime->lock, FuriWaitForever);
    bool active = runtime->text_input_active && runtime->generation == generation &&
                  runtime->module && runtime->state && runtime->module->on_text_input;
    bool valid = false;
    char result[C5_TEXT_INPUT_VALUE_CAPACITY];
    if(active) {
        if(!accepted) {
            valid = true;
        } else if(text && length < runtime->text_input.capacity &&
                  length >= runtime->text_input.minimum_length && !memchr(text, '\0', length)) {
            memcpy(result, text, length);
            result[length] = '\0';
            valid = true;
        }
        runtime->text_input_active = false;
        runtime->module->on_text_input(
            runtime->state, &runtime->host, valid && accepted, valid && accepted ? result : "");
        c5_secure_clear(&runtime->text_input, sizeof(runtime->text_input));
    }
    c5_secure_clear(result, sizeof(result));
    furi_mutex_release(runtime->lock);
    return valid;
}
