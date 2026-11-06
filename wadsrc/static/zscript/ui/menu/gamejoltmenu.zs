/*
** Game Jolt login menu widgets.
** SPDX-License-Identifier: GPL-3.0-or-later
*/

class OptionMenuItemGameJoltTokenField : OptionMenuItemTextField
{
	override String Represent()
	{
		String value = mEnter ? mEnter.GetText() : GetCVarString();
		String masked = "";
		for (uint i = 0; i < value.Length(); i++) masked.AppendCharacter(42);
		if (mEnter) masked = masked .. Menu.OptionFont().GetCursor();
		return masked;
	}
}

class OptionMenuItemGameJoltPrivateKeyField : OptionMenuItemTextField
{
	override String Represent()
	{
		String value = mEnter ? mEnter.GetText() : "";
		if (!mEnter) return GameJolt.HasPrivateKey() ? "********" : "Not set";
		String masked = "";
		for (uint i = 0; i < value.Length(); i++) masked.AppendCharacter(42);
		return masked .. Menu.OptionFont().GetCursor();
	}

	override bool, String GetString(int i)
	{
		return i == 0, "";
	}

	override bool SetString(int i, String value)
	{
		if (i != 0) return false;
		return GameJolt.SetPrivateKey(value);
	}
}

class OptionMenuItemGameJoltLogin : OptionMenuItemSubmenu
{
	OptionMenuItemGameJoltLogin Init(String label)
	{
		Super.Init(label, 'GameJoltLogin');
		return self;
	}

	override bool Activate()
	{
		Menu.MenuSound("menu/choose");
		GameJolt.Authenticate();
		return true;
	}
}

class OptionMenuItemGameJoltRefresh : OptionMenuItemSubmenu
{
	OptionMenuItemGameJoltRefresh Init(String label)
	{
		Super.Init(label, 'GameJoltRefresh');
		return self;
	}

	override bool Activate()
	{
		Menu.MenuSound("menu/choose");
		GameJolt.FetchTrophies();
		return true;
	}
}

class OptionMenuItemGameJoltStatus : OptionMenuItemStaticText
{
	override int Draw(OptionMenuDescriptor desc, int y, int indent, bool selected)
	{
		Super.Draw(desc, y, indent, selected);
		String status = GameJolt.IsAuthenticated() ? "Connected" : "Disconnected";
		drawValue(indent, y, OptionMenuSettings.mFontColorValue, status, false, false);
		return indent;
	}
}
