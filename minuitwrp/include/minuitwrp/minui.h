/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MINUI_H_
#define _MINUI_H_

#include "gui/placement.h"
#include <stdbool.h>

struct GRSurface {
    int width;
    int height;
    int row_bytes;
    int pixel_bytes;
    unsigned char* data;
    __u32 format;
};

typedef void* gr_surface;
typedef unsigned short gr_pixel;

#define FONT_TYPE_TWRP 0
#define FONT_TYPE_TTF  1

int gr_init(void);
void gr_exit(void);

int gr_fb_width(void);
int gr_fb_height(void);
gr_pixel *gr_fb_data(void);
void gr_flip(void);
// Set the damage for the NEXT gr_flip (logical coordinates, before rotation -- like
// gr_clip/gr_fill). If the call is omitted before gr_flip, the backend copies the
// full frame (original behavior). Enables partial flipping (only the changed
// display rows) instead of the full framebuffer memcpy.
void gr_set_flip_damage(int x, int y, int w, int h);
void gr_fb_blank(bool blank);

void gr_color(unsigned char r, unsigned char g, unsigned char b, unsigned char a);
void gr_clip(int x, int y, int w, int h);
void gr_noclip();
// Set the scissor to the INTERSECTION of (x,y,w,h) with the currently active
// gr_clip rect (without an active clip identical to gr_clip). For widgets that clip
// internally (GUIScrollList/GUIInput), so they do not break out of the page's
// region scissor in the region-render path. 1-slot save, NOT nestable: exactly ONE
// gr_clip_intersect() ... gr_clip_restore() pair per widget render (restores the
// prior state).
void gr_clip_intersect(int x, int y, int w, int h);
void gr_clip_restore();
void gr_fill(int x, int y, int w, int h);
void gr_line(int x0, int y0, int x1, int y1, int width);
gr_surface gr_render_circle(int radius, unsigned char r, unsigned char g, unsigned char b, unsigned char a);

int gr_textEx_scaleW(int x, int y, const char *s, void* pFont, int max_width, int placement, int scale);

int gr_getMaxFontHeight(void *font);

void *gr_ttf_loadFont(const char *filename, int size, int dpi);
void *gr_ttf_scaleFont(void *font, int max_width, int measured_width);
void gr_ttf_freeFont(void *font);
int gr_ttf_textExWH(void *context, int x, int y, const char *s, void *pFont,
                    int max_width, int max_height, const gr_surface gr_draw);
int gr_ttf_measureEx(const char *s, void *font);
int gr_ttf_maxExW(const char *s, void *font, int max_width);
int gr_ttf_getMaxFontHeight(void *font);
void gr_ttf_dump_stats(void);

void gr_blit(gr_surface source, int sx, int sy, int w, int h, int dx, int dy);
unsigned int gr_get_width(gr_surface surface);
unsigned int gr_get_height(gr_surface surface);
// Opaque-x span of a surface (leftmost/rightmost visible pixel, alpha > 8).
// Return 1 + minx/maxx (surface pixel coordinates) for an alpha-capable format
// (RGBA/BGRA_8888); 0 if no usable alpha channel (e.g. RGBX_8888) -> the caller
// must then use the full rect. For an empty (fully transparent) surface minx/maxx
// are set to -1 (return stays 1).
int gr_surface_opaque_xspan(gr_surface surface, int* minx, int* maxx);
int gr_get_surface(gr_surface* surface);
int gr_free_surface(gr_surface surface);

// Functions in graphics_utils.c
int gr_save_screenshot(const char *dest);

// Transform minuitwrp API coordinates into display coordinates,
// for panels that are hardware-mounted in a rotated manner.
int ROTATION_X_DISP(int x, int y, int w);

int ROTATION_Y_DISP(int x, int y, int h);

void surface_ROTATION_transform(gr_surface dst_ptr, const gr_surface src_ptr, size_t num_bytes_per_pixel);

// input event structure, include <linux/input.h> for the definition.
// see http://www.mjmwired.net/kernel/Documentation/input/ for info.
struct input_event;

int ev_init(void);
void ev_exit(void);
int ev_get(struct input_event *ev, int timeout_ms);
int ev_has_mouse(void);

// Resources

// Returns 0 if no error, else negative.
int res_create_surface(const char* name, gr_surface* pSurface);
void res_free_surface(gr_surface surface);
int res_scale_surface(gr_surface source, gr_surface* destination, float scale_w, float scale_h);

int vibrate(int timeout_ms);

#endif
