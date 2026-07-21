/*
        Copyright 2012 to 2020 TeamWin
        This file is part of TWRP/TeamWin Recovery Project.

        TWRP is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        TWRP is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with TWRP.  If not, see <http://www.gnu.org/licenses/>.
*/

// text.cpp - GUIText object

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#include <string>

extern "C" {
#include "../twcommon.h"
}
#include "minuitwrp/minui.h"
#include "minuitwrp/truetype.hpp"

#include "rapidxml.hpp"
#include "objects.hpp"

GUIText::GUIText(xml_node<>* node)
	: GUIObject(node)
{
	mFont = NULL;
	mIsStatic = 1;
	mVarChanged = 0;
	mFontHeight = 0;
	maxWidth = 0;
	scaleWidth = true;
	isHighlighted = false;
	mText = "";
	mBoundsX = mBoundsY = mBoundsW = mBoundsH = 0;
	mBoundsKnown = false;

	if (!node)
		return;

	// Load colors
	mColor = LoadAttrColor(node, "color", COLOR(0,0,0,255));
	mHighlightColor = LoadAttrColor(node, "highlightcolor", mColor);

	// Load the font, and possibly override the color
	mFont = LoadAttrFont(FindNode(node, "font"), "resource");
	if (!mFont || !mFont->GetResource())
		return;
	mColor = LoadAttrColor(FindNode(node, "font"), "color", mColor);
	mHighlightColor = LoadAttrColor(FindNode(node, "font"), "highlightcolor", mColor);

	// Load the placement
	LoadPlacement(FindNode(node, "placement"), &mRenderX, &mRenderY, &mRenderW, &mRenderH, &mPlacement);

	xml_node<>* child = FindNode(node, "text");
	if (child)  mText = child->value();

	child = FindNode(node, "noscaling");
	if (child) {
		scaleWidth = false;
	} else {
		if (mPlacement == TOP_LEFT || mPlacement == BOTTOM_LEFT) {
			maxWidth = gr_fb_width() - mRenderX;
		} else if (mPlacement == TOP_RIGHT || mPlacement == BOTTOM_RIGHT) {
			maxWidth = mRenderX;
		} else if (mPlacement == CENTER || mPlacement == CENTER_X_ONLY) {
			if (mRenderX < gr_fb_width() / 2) {
				maxWidth = mRenderX * 2;
			} else {
				maxWidth = (gr_fb_width() - mRenderX) * 2;
			}
		}
	}

	// Simple way to check for static state
	mLastValue = gui_parse_text(mText);
	if (mLastValue != mText)   mIsStatic = 0;

	mFontHeight = mFont->GetHeight();
}

int GUIText::Render(void)
{
	if (!isConditionTrue())
		return 0;

	void* fontResource = NULL;
	if (mFont)
		fontResource = mFont->GetResource();
	else
		return -1;

	mLastValue = gui_parse_text(mText);

	mVarChanged = 0;

	if (isHighlighted)
		gr_color(mHighlightColor.red, mHighlightColor.green, mHighlightColor.blue, mHighlightColor.alpha);
	else
		gr_color(mColor.red, mColor.green, mColor.blue, mColor.alpha);

	gr_textEx_scaleW(mRenderX, mRenderY, mLastValue.c_str(), fontResource, maxWidth, mPlacement, scaleWidth);

	// Set the bbox once when still unknown. Static texts never go through Update()
	// -> only here (on the page's first full render) do they get a bbox and become
	// skippable in RenderRegion afterwards. Dynamic texts keep their bbox current via
	// Update(), so here it is only a fallback.
	if (!mBoundsKnown) {
		int w = (maxWidth > 0) ? (int)maxWidth
		                       : twrpTruetype::gr_ttf_measureEx(mLastValue.c_str(), fontResource);
		StoreBounds(w);
	}

	return 0;
}

int GUIText::Update(void)
{
	if (!isConditionTrue())
		return 0;

	static int updateCounter = 3;

	// This hack just makes sure we update at least once a minute for things like clock and battery
	if (updateCounter)  updateCounter--;
	else
	{
		mVarChanged = 1;
		updateCounter = 3;
	}

	if (mIsStatic || !mVarChanged)
		return 0;

	std::string newValue = gui_parse_text(mText);
	if (mLastValue == newValue)
		return 0;

	// No full render; instead register this text's damage region and return 1. The
	// rect is a SUPERSET of the actually painted area (covers old AND new text -> no
	// ghosting when shrinking). The x/y shift per placement mirrors gr_textEx_scaleW()
	// exactly.
	int w;
	if (maxWidth > 0) {
		// scaleWidth: text is capped at maxWidth -> maxWidth covers old+new.
		w = (int)maxWidth;
	} else {
		// noscaling: measure the old (mLastValue, not yet overwritten) and new width,
		// take the maximum (covers shrinking).
		void* fontResource = mFont ? mFont->GetResource() : NULL;
		int wNew = twrpTruetype::gr_ttf_measureEx(newValue.c_str(), fontResource);
		int wOld = twrpTruetype::gr_ttf_measureEx(mLastValue.c_str(), fontResource);
		w = (wOld > wNew) ? wOld : wNew;
	}

	mLastValue = newValue;

	// Compute and cache the bbox from the superset width (serves both as the
	// requested damage region AND as skip-bounds for future RenderRegion calls of
	// other objects, e.g. the animation).
	StoreBounds(w);
	if (!mBoundsKnown) {
		return 2; // degenerate rect -> full render to be safe
	}

	PageManager::RequestFrameRegion(mBoundsX, mBoundsY, mBoundsW, mBoundsH);
	return 1;
}

void GUIText::StoreBounds(int w)
{
	int h = mFontHeight;

	int bx = mRenderX;
	if (mPlacement != TOP_LEFT && mPlacement != BOTTOM_LEFT && mPlacement != TEXT_ONLY_RIGHT) {
		if (mPlacement == CENTER || mPlacement == CENTER_X_ONLY)
			bx = mRenderX - (w / 2);
		else
			bx = mRenderX - w;
	}
	int by = mRenderY;
	if (mPlacement != TOP_LEFT && mPlacement != TOP_RIGHT) {
		if (mPlacement == CENTER || mPlacement == TEXT_ONLY_RIGHT)
			by = mRenderY - (h / 2);
		else if (mPlacement == BOTTOM_LEFT || mPlacement == BOTTOM_RIGHT)
			by = mRenderY - h;
	}

	// small margin for anti-aliasing/descenders
	bx -= 1; by -= 1; w += 2; h += 2;

	// clamp to the screen
	if (bx < 0) { w += bx; bx = 0; }
	if (by < 0) { h += by; by = 0; }
	int fbw = gr_fb_width();
	int fbh = gr_fb_height();
	if (bx + w > fbw) w = fbw - bx;
	if (by + h > fbh) h = fbh - by;
	if (w <= 0 || h <= 0) {
		mBoundsKnown = false;
		return;
	}

	mBoundsX = bx;
	mBoundsY = by;
	mBoundsW = w;
	mBoundsH = h;
	mBoundsKnown = true;
}

bool GUIText::GetClipBounds(int& x, int& y, int& w, int& h)
{
	if (!mBoundsKnown)
		return false;
	x = mBoundsX;
	y = mBoundsY;
	w = mBoundsW;
	h = mBoundsH;
	return true;
}

int GUIText::GetCurrentBounds(int& w, int& h)
{
	void* fontResource = NULL;

	if (mFont)
		fontResource = mFont->GetResource();

	h = mFontHeight;
	mLastValue = gui_parse_text(mText);
	w = twrpTruetype::gr_ttf_measureEx(mLastValue.c_str(), fontResource);
	return 0;
}

int GUIText::NotifyVarChange(const std::string& varName, const std::string& value)
{
	GUIObject::NotifyVarChange(varName, value);

	mVarChanged = 1;
	return 0;
}

int GUIText::SetMaxWidth(unsigned width)
{
	maxWidth = width;
	if (!maxWidth)
		scaleWidth = false;
	mVarChanged = 1;
	return 0;
}

void GUIText::SetText(string newtext)
{
	mText = newtext;
}
