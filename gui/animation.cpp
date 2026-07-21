/*
	Copyright 2017 TeamWin
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

// animation.cpp - GUIAnimation object

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

#include "rapidxml.hpp"
#include "objects.hpp"


GUIAnimation::GUIAnimation(xml_node<>* node) : GUIObject(node)
{
	xml_node<>* child;

	mAnimation = NULL;
	mFrame = 1;
	mFPS = 1;
	mLoop = -1;
	mRender = 1;
	mUpdateCount = 0;
	// Frame-bounds cache (filled lazily on the first Update)
	mFrameBoundsReady = false;
	mFrameBoundsUsable = false;

	if (!node)  return;

	mAnimation = LoadAttrAnimation(FindNode(node, "resource"), "name");

	// Load the placement
	LoadPlacement(FindNode(node, "placement"), &mRenderX, &mRenderY, NULL, NULL, &mPlacement);

	child = FindNode(node, "speed");
	if (child)
	{
		mFPS = LoadAttrInt(child, "fps", mFPS);
		mRender = LoadAttrInt(child, "render", mRender);
	}
	if (mFPS > 30)  mFPS = 30;

	child = FindNode(node, "loop");
	if (child)
	{
		xml_attribute<>* attr = child->first_attribute("frame");
		if (attr)
			mLoop = atoi(attr->value()) - 1;
		mFrame = LoadAttrInt(child, "start", mFrame);
	}

	// Fetch the render sizes
	if (mAnimation && mAnimation->GetResource())
	{
		mRenderW = mAnimation->GetWidth();
		mRenderH = mAnimation->GetHeight();

		// Adjust for placement
		if (mPlacement != TOP_LEFT && mPlacement != BOTTOM_LEFT)
		{
			if (mPlacement == CENTER)
				mRenderX -= (mRenderW / 2);
			else
				mRenderX -= mRenderW;
		}
		if (mPlacement != TOP_LEFT && mPlacement != TOP_RIGHT)
		{
			if (mPlacement == CENTER)
				mRenderY -= (mRenderH / 2);
			else
				mRenderY -= mRenderH;
		}
		SetPlacement(TOP_LEFT);
	}
}

int GUIAnimation::Render(void)
{
	if (!isConditionTrue())
		return 0;

	if (!mAnimation || !mAnimation->GetResource(mFrame))	return -1;

	gr_blit(mAnimation->GetResource(mFrame), 0, 0, mRenderW, mRenderH, mRenderX, mRenderY);
	return 0;
}

// Scan each frame's opaque-x bbox of the surface (once, lazily). The indeterminate
// shimmer is a narrow moving block on an otherwise transparent frame -> only those
// columns need redrawing per tick. Surfaces are device-scaled -> the x-bounds are
// device coordinates directly (relative to the surface).
void GUIAnimation::ComputeFrameBounds(void)
{
	mFrameBoundsReady = true;
	mFrameBoundsUsable = false;
	if (!mAnimation) return;
	int count = mAnimation->GetResourceCount();
	if (count <= 0) return;
	mFrameMinX.assign(count, -1);
	mFrameMaxX.assign(count, -1);
	for (int f = 0; f < count; f++) {
		int minx = -1, maxx = -1;
		// gr_surface_opaque_xspan knows the correct GGLSurface layout (minuitwrp).
		// Return 0 = no usable alpha channel -> localization uncertain -> full
		// fallback (mFrameBoundsUsable stays false -> Update takes the full rect).
		if (!gr_surface_opaque_xspan(mAnimation->GetResource(f), &minx, &maxx))
			return;
		mFrameMinX[f] = minx; // -1 for a fully transparent frame (ok)
		mFrameMaxX[f] = maxx;
	}
	mFrameBoundsUsable = true;
}

int GUIAnimation::Update(void)
{
	if (!isConditionTrue())
		return 0;

	if (!mAnimation)		return -1;

	// Handle the "end-of-animation" state
	if (mLoop == -2)		return 0;

	// Determine if we need the next frame yet...
	if (++mUpdateCount > 30 / mFPS)
	{
		mUpdateCount = 0;
		int oldFrame = mFrame; // K11: frame BEFORE the advance (vacated shimmer position)
		if (++mFrame >= mAnimation->GetResourceCount())
		{
			if (mLoop < 0)
			{
				mFrame = mAnimation->GetResourceCount() - 1;
				mLoop = -2;
			}
			else
				mFrame = mLoop;
		}
		if (mRender == 2) {
			// Instead of a full render, regionally redraw only the animation rect --
			// and NOT the full rect but only the shimmer zone = the union of the
			// opaque bbox of old + new frame (the old position must be erased, the new
			// one painted). The shimmer is narrow -> ~1/4 of the width. Page::RenderRegion
			// clips animation + overlapping progressbar + fill to this strip. return 1
			// -> the GUI loop does RenderRegion + flip.
			if (!mFrameBoundsReady)
				ComputeFrameBounds();
			int rx = -1, rw = 0;
			if (mFrameBoundsUsable) {
				int n = (int)mFrameMinX.size();
				int a0 = (oldFrame >= 0 && oldFrame < n) ? mFrameMinX[oldFrame] : -1;
				int a1 = (oldFrame >= 0 && oldFrame < n) ? mFrameMaxX[oldFrame] : -1;
				int b0 = (mFrame   >= 0 && mFrame   < n) ? mFrameMinX[mFrame]   : -1;
				int b1 = (mFrame   >= 0 && mFrame   < n) ? mFrameMaxX[mFrame]   : -1;
				int lo = -1, hi = -1;
				if (a0 >= 0) { lo = a0; hi = a1; }
				if (b0 >= 0) { if (lo < 0 || b0 < lo) lo = b0; if (b1 > hi) hi = b1; }
				if (lo >= 0 && hi >= lo) {
					// AA margin, resolution-scaled. The indeterminate shimmer has a 1008 px
					// source width and is scaled to mRenderW (=mAnimation->GetWidth()) ->
					// margin in SOURCE pixels, scaled up by mRenderW/1008. SRC_M=3 gives 4 px
					// at mRenderW=1344, resolution-independent.
					const int SRC_W = 1008; // source width of the shimmer image
					const int SRC_M = 3;    // margin in source pixels (-> 4 px @1344)
					const int m = (SRC_M * mRenderW + SRC_W / 2) / SRC_W; // +SRC_W/2 = rounding
					rx = lo - m;
					rw = (hi - lo + 1) + 2 * m;
					if (rx < 0) { rw += rx; rx = 0; }
					if (rx + rw > mRenderW) rw = mRenderW - rx;
				}
			}
			if (rx >= 0 && rw > 0 && rw < mRenderW) {
				PageManager::RequestFrameRegion(mRenderX + rx, mRenderY, rw, mRenderH);
			} else {
				// Fallback (no alpha / both frames empty / strip ~ full width):
				// full rect (safe, original behavior).
				PageManager::RequestFrameRegion(mRenderX, mRenderY, mRenderW, mRenderH);
			}
			return 1;
		}
		// render!=2 was the last self-drawing path -- an unclipped direct render out of
		// Update() that in the region/overlay regime would paint past the region scissor
		// AND the overlay alpha blend (mRender defaults to 1!). Unified: register the full
		// animation bounds as a damage region; the GUI loop renders them clipped and in
		// correct Z-order (incl. overlays). All 5 project themes use render="2" (branch
		// above) -- this hardens custom themes. Bounds unknown/0 -> full render (safe).
		if (mRenderW <= 0 || mRenderH <= 0)
			return 2;
		PageManager::RequestFrameRegion(mRenderX, mRenderY, mRenderW, mRenderH);
		return 1;
	}
	return 0;
}

