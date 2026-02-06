#include "app.h"
#include "uart_comm.h"
#include "screen_main_menu.h"
#include "screen.h"
#include <furi_hal.h>
#include <string.h>

int32_t wifi_attacks_app(void* p) {
    UNUSED(p);
    
    WiFiApp* app = (WiFiApp*)malloc(sizeof(WiFiApp));
    if(!app) return -1;
    memset(app, 0, sizeof(WiFiApp));
    
    // Initialize GUI
    app->gui = furi_record_open(RECORD_GUI);
    if(!app->gui) {
        free(app);
        return -1;
    }
    app->view_dispatcher = view_dispatcher_alloc();
    if(!app->view_dispatcher) {
        furi_record_close(RECORD_GUI);
        free(app);
        return -1;
    }
    app->view_stack = view_stack_alloc();
    
    view_dispatcher_enable_queue(app->view_dispatcher);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    
    // Initialize UART
    uart_comm_init(app);
    
    // Initialize app state
    app->networks = NULL;
    app->network_count = 0;
    memset(app->selected_networks, 0, sizeof(app->selected_networks));
    app->selected_count = 0;
    
    app->attack_status = furi_string_alloc();
    app->attack_log = furi_string_alloc();
    app->current_ssid = furi_string_alloc();
    app->current_password = furi_string_alloc();
    app->attack_in_progress = false;
    
    app->sniffer_packet_count = 0;
    app->evil_twin_html_selection = 0;
    app->html_files = NULL;
    app->html_file_count = 0;
    app->evil_twin_password = furi_string_alloc();
    
    // Create and push main menu
    View* main_menu = screen_main_menu_create(app);
    if(!main_menu) {
        uart_comm_deinit(app);
        view_dispatcher_free(app->view_dispatcher);
        view_stack_free(app->view_stack);
        furi_record_close(RECORD_GUI);
        free(app);
        return -1;
    }
    screen_push(app, main_menu);
    
    // Main event loop
    while(1) {
        furi_delay_ms(100);
        // TODO: Handle events
    }
    
    // Cleanup
    uart_comm_deinit(app);
    
    furi_string_free(app->attack_status);
    furi_string_free(app->attack_log);
    furi_string_free(app->current_ssid);
    furi_string_free(app->current_password);
    furi_string_free(app->evil_twin_password);
    
    for(uint32_t i = 0; i < app->network_count; i++) {
        free(app->networks[i]);
    }
    if(app->networks) free(app->networks);
    
    for(uint32_t i = 0; i < app->html_file_count; i++) {
        free(app->html_files[i]);
    }
    if(app->html_files) free(app->html_files);
    
    view_dispatcher_free(app->view_dispatcher);
    view_stack_free(app->view_stack);
    furi_record_close(RECORD_GUI);
    
    free(app);
    
    return 0;
}
