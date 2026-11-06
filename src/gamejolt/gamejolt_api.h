/*
** gamejolt_api.h
**
** SPDX-License-Identifier: GPL-3.0-or-later
*/

#pragma once

#include "tarray.h"
#include "zstring.h"

struct FGJTrophy
{
	int Id = 0;
	FString Title;
	FString Description;
	FString Difficulty;
	bool Achieved = false;
};

void GameJolt_Authenticate();
bool GameJolt_SetPrivateKey(const char* key);
bool GameJolt_HasPrivateKey();
void GameJolt_UnlockTrophy(int trophyId);
void GameJolt_FetchTrophies();
bool GameJolt_IsAuthenticated();
bool GameJolt_IsTrophyAchieved(int trophyId);
const TArray<FGJTrophy>& GameJolt_GetTrophies();
void GameJolt_Tick();
