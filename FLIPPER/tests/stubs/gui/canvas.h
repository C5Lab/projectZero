#pragma once

#include <stddef.h>

typedef struct {
    char lines[16][96];
    size_t line_count;
    size_t box_count;
    size_t rbox_count;
    size_t rframe_count;
} Canvas;

typedef enum { ColorBlack, ColorWhite } Color;
typedef enum { FontPrimary, FontSecondary } Font;
typedef enum { AlignCenter } Align;

void canvas_set_color(Canvas* canvas, Color color);
void canvas_set_font(Canvas* canvas, Font font);
void canvas_draw_str(Canvas* canvas, int x, int y, const char* text);
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height);
void canvas_draw_rbox(Canvas* canvas, int x, int y, int width, int height, int radius);
void canvas_draw_rframe(Canvas* canvas, int x, int y, int width, int height, int radius);
void canvas_draw_str_aligned(
    Canvas* canvas,
    int x,
    int y,
    Align horizontal,
    Align vertical,
    const char* text);
