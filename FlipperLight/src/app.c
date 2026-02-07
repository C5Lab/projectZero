#include "app.h"
#include "uart_comm.h"
#include "screen_main_menu.h"
#include "screen.h"
#include <furi_hal.h>
#include <storage/storage.h>
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
    
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    
    // Initialize UART
    uart_comm_init(app);
    
    // Check initial board connection
    furi_delay_ms(500); // Give board time to initialize
    app->board_connected = uart_check_board_connection(app);
    
    // Initialize app state
    app->networks = NULL;
    app->network_count = 0;
    memset(app->selected_networks, 0, sizeof(app->selected_networks));
    app->selected_count = 0;
    
    // Initialize scanning state
    app->scan_results = NULL;
    app->scan_result_count = 0;
    app->scan_result_capacity = 0;
    app->scanning_in_progress = false;
    app->scan_bytes_received = 0;
    app->last_scan_line = furi_string_alloc();
    
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
    
    // Load red team mode from persistent storage
    app->red_team_mode = false;
    {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        File* file = storage_file_alloc(storage);
        if(storage_file_open(file, APP_DATA_PATH("redteam.conf"), FSAM_READ, FSOM_OPEN_EXISTING)) {
            uint8_t val = 0;
            if(storage_file_read(file, &val, 1) == 1) {
                app->red_team_mode = (val == 1);
            }
        }
        storage_file_close(file);
        storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
    }
    
    // Create and push main menu with cleanup
    void* main_menu_data = NULL;
    View* main_menu = screen_main_menu_create(app, &main_menu_data);
    if(!main_menu) {
        uart_comm_deinit(app);
        view_dispatcher_free(app->view_dispatcher);
        view_stack_free(app->view_stack);
        furi_record_close(RECORD_GUI);
        free(app);
        return -1;
    }
    
    // Use screen_push_with_cleanup for main menu too
    screen_push_with_cleanup(app, main_menu, main_menu_cleanup_internal, main_menu_data);
    
    // Run the ViewDispatcher event loop
    view_dispatcher_run(app->view_dispatcher);
    
    // Cleanup - remove all views first
    screen_pop_all(app);
    
    uart_comm_deinit(app);
    
    furi_string_free(app->attack_status);
    furi_string_free(app->attack_log);
    furi_string_free(app->current_ssid);
    furi_string_free(app->current_password);
    furi_string_free(app->evil_twin_password);
    furi_string_free(app->last_scan_line);
    
    if(app->scan_results) free(app->scan_results);
    
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
