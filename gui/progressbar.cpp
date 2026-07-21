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

// progressbar.cpp - GUIProgressBar object

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

GUIProgressBar::GUIProgressBar(xml_node<>* node) : GUIObject(node)
{
	xml_node<>* child;

	mEmptyBar = NULL;
	mFullBar = NULL;
	mLastPos = 0;
	mSlide = 0.0;
	mSlideInc = 0.0;

	if (!node)
	{
		LOGERR("GUIProgressBar created without XML node\n");
		return;
	}

	child = FindNode(node, "resource");
	if (child)
	{
		mEmptyBar = LoadAttrImage(child, "empty");
		mFullBar = LoadAttrImage(child, "full");
	}

	// Load the placement
	LoadPlacement(FindNode(node, "placement"), &mRenderX, &mRenderY);

	// Load the data
	child = FindNode(node, "data");
	if (child)
	{
		mMinValVar = LoadAttrString(child, "min");
		mMaxValVar = LoadAttrString(child, "max");
		mCurValVar = LoadAttrString(child, "name");
	}

	if (mEmptyBar && mEmptyBar->GetResource()) {
		mRenderW = mEmptyBar->GetWidth();
		mRenderH = mEmptyBar->GetHeight();
	} else {
		mRenderW = mRenderH = 0;
	}
}

int GUIProgressBar::Render(void)
{
	if (!isConditionTrue())
		return 0;

	// This handles making sure timing updates occur
	Update();
	return RenderInternal();
}

int GUIProgressBar::RenderInternal(void)
{
	if (!mEmptyBar || !mEmptyBar->GetResource())
		return -1;

	if (!mFullBar || !mFullBar->GetResource())
		return -1;

	gr_blit(mEmptyBar->GetResource(), 0, 0, mRenderW, mRenderH, mRenderX, mRenderY);
	gr_blit(mFullBar->GetResource(), 0, 0, mLastPos, mRenderH, mRenderX, mRenderY);
	return 0;
}

int GUIProgressBar::Update(void)
{
	if (!isConditionTrue())
		return 0;

	std::string str;
	int min, max, cur, pos;

	if (mMinValVar.empty())
		min = 0;
	else
	{
		str.clear();
		if (atoi(mMinValVar.c_str()) != 0)
			str = mMinValVar;
		else
			DataManager::GetValue(mMinValVar, str);
		min = atoi(str.c_str());
	}

	if (mMaxValVar.empty())
		max = 100;
	else
	{
		str.clear();
		if (atoi(mMaxValVar.c_str()) != 0)
			str = mMaxValVar;
		else
			DataManager::GetValue(mMaxValVar, str);
		max = atoi(str.c_str());
	}

	str.clear();
	DataManager::GetValue(mCurValVar, str);
	cur = atoi(str.c_str());

	// Do slide, if needed
	if (mSlideFrames)
	{
		mSlide += mSlideInc;
		mSlideFrames--;
		if (cur != (int) mSlide)
		{
			cur = (int) mSlide;
			DataManager::SetValue(mCurValVar, cur);
		}
	}

	// Normalize to 0
	max -= min;
	cur -= min;
	min = 0;

	if (cur < min)
		cur = min;
	if (cur > max)
		cur = max;

	if (max == 0)
		pos = 0;
	else
		pos = (cur * mRenderW) / max;

	if (pos == mLastPos)
		return 0;

	int prevPos = mLastPos;
	mLastPos = pos;

	// No full render and no unclipped self-render; just register the damage region
	// and return 1. RenderRegion redraws the bar (its Render() calls RenderInternal)
	// clipped. mRenderW/mRenderH are the real bar bounds.
	//
	// Register ONLY the changed fill strip [prevPos..pos] as damage, not the whole
	// bar. progress_fill is horizontally uniform in the body (solid color), only the
	// rounded cap left/right is x-dependent -> the sliver is color-true if it also
	// covers the cap (cap margin). Since animation + progressbar lie exactly on top
	// of each other, in frames WITHOUT an animation tick Page::RenderRegion now clips
	// animation + bar + fill to this narrow strip instead of full-width.
	int lo = (prevPos < pos) ? prevPos : pos;
	int hi = (prevPos < pos) ? pos : prevPos;
	// AA margin, resolution-scaled. progress_fill has a 1008 px source width and is
	// scaled to mRenderW (=mEmptyBar->GetWidth()) -> define the margin in SOURCE
	// pixels and scale it up by the same factor mRenderW/1008. SRC_CAP=9 gives 12 px
	// at mRenderW=1344, staying theme-/resolution-independent.
	const int SRC_W   = 1008; // source width of the bar image
	const int SRC_CAP = 9;    // margin in source pixels (-> 12 px @1344)
	const int cap = (SRC_CAP * mRenderW + SRC_W / 2) / SRC_W; // +SRC_W/2 = rounding
	int sx = mRenderX + lo - cap;
	int sw = (hi - lo) + 2 * cap;
	if (sx < mRenderX) { sw -= (mRenderX - sx); sx = mRenderX; }
	if (sx + sw > mRenderX + mRenderW) sw = mRenderX + mRenderW - sx;
	if (prevPos == 0 || pos == 0 || sw >= mRenderW || sw <= 0) {
		// First start/reset or strip ~ full bar -> request the whole bar (safe).
		PageManager::RequestFrameRegion(mRenderX, mRenderY, mRenderW, mRenderH);
	} else {
		PageManager::RequestFrameRegion(sx, mRenderY, sw, mRenderH);
	}
	return 1;
}

int GUIProgressBar::NotifyVarChange(const std::string& varName, const std::string& value)
{
	GUIObject::NotifyVarChange(varName, value);

	if (!isConditionTrue())
		return 0;

	static int nextPush = 0;

	if (varName.empty())
	{
		nextPush = 0;
		mLastPos = 0;
		mSlide = 0.0;
		mSlideInc = 0.0;
		return 0;
	}

	if (varName == "ui_progress_portion" || varName == "ui_progress_frames")
	{
		std::string str;
		int cur;

		if (mSlideFrames)
		{
			mSlide += (mSlideInc * mSlideFrames);
			cur = (int) mSlide;
			DataManager::SetValue(mCurValVar, cur);
			mSlideFrames = 0;
		}

		if (nextPush)
		{
			mSlide += nextPush;
			cur = (int) mSlide;
			DataManager::SetValue(mCurValVar, cur);
			nextPush = 0;
		}

		if (varName == "ui_progress_portion")   mSlide = atof(value.c_str());
		else
		{
			mSlideFrames = atol(value.c_str());
			if (mSlideFrames == 0)
			{
				// We're just holding this progress until the next push
				nextPush = mSlide;
			}
		}

		if (mSlide > 0 && mSlideFrames > 0)
		{
			// Get the current position
			str.clear();
			DataManager::GetValue(mCurValVar, str);
			cur = atoi(str.c_str());

			mSlideInc = (float) mSlide / (float) mSlideFrames;
			mSlide = cur;
		}
	}
	return 0;
}
