/*
** gamejolt_api.cpp
**
** Asynchronous Game Jolt Game API client.
** SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "c_cvars.h"
#include "curl_loader.h"
#include "curl_loader_internal.h"
#include "base64.h"
#include "i_specialpaths.h"
#include "md5.h"
#include "printf.h"
#include "rapidjson/document.h"
#include "sbar.h"
#include "gamejolt_api.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#endif

CVAR(Int, gamejolt_game_id, 0, CVAR_ARCHIVE | CVAR_GLOBALCONFIG)
CVAR(String, gamejolt_username, "", CVAR_ARCHIVE | CVAR_GLOBALCONFIG)
CVAR(String, gamejolt_usertoken, "", CVAR_ARCHIVE | CVAR_GLOBALCONFIG | CVAR_HIDDEN)
CVAR(String, gamejolt_pending_trophies, "", CVAR_ARCHIVE | CVAR_GLOBALCONFIG | CVAR_HIDDEN | CVAR_NOSET)

namespace
{
	constexpr char ApiRoot[] = "https://api.gamejolt.com/api/game/v1_2/";
	// DPAPI provides the real encryption; this fixed optional entropy is not a secret.
	constexpr char VaultPassword[] = "InsertYourPasswordHere";
	using Clock = std::chrono::steady_clock;
	FString PrivateKeyValue;
	bool PrivateKeyLoaded = false;
	bool PrivateKeyAvailable = false;

	FString PrivateKeyVaultPath()
	{
		return M_GetConfigPath(false) + ".gamejolt-private-key.b64";
	}

	bool WritePrivateKeyVault(const std::string& encoded)
	{
#ifdef _WIN32
		const auto path = PrivateKeyVaultPath().WideString();
		HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) return false;
		DWORD written = 0;
		const DWORD length = (DWORD)encoded.size();
		const BOOL success = WriteFile(file, encoded.data(), length, &written, nullptr);
		CloseHandle(file);
		return success && written == length;
#else
		(void)encoded;
		return false;
#endif
	}

	bool ReadPrivateKeyVault(std::string& encoded)
	{
#ifdef _WIN32
		const auto path = PrivateKeyVaultPath().WideString();
		HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) return false;
		const DWORD length = GetFileSize(file, nullptr);
		if (length == INVALID_FILE_SIZE || length == 0 || length > 16384)
		{
			CloseHandle(file);
			return false;
		}
		encoded.resize(length);
		DWORD read = 0;
		const BOOL success = ReadFile(file, encoded.data(), length, &read, nullptr);
		CloseHandle(file);
		if (!success || read != length) return false;
		while (!encoded.empty() && (encoded.back() == '\r' || encoded.back() == '\n' || encoded.back() == ' ' || encoded.back() == '\t'))
			encoded.pop_back();
		return !encoded.empty();
#else
		(void)encoded;
		return false;
#endif
	}

	bool ProtectPrivateKey(const char* key, std::string& encoded)
	{
#ifdef _WIN32
		const size_t keyLength = strlen(key);
		if (keyLength == 0 || keyLength > 4096 || keyLength > MAXDWORD) return false;
		DATA_BLOB input{(DWORD)keyLength, (BYTE*)key};
		DATA_BLOB entropy{(DWORD)(sizeof(VaultPassword) - 1), (BYTE*)VaultPassword};
		DATA_BLOB protectedData{};
		if (!CryptProtectData(&input, L"UZDoom Game Jolt private key", &entropy, nullptr, nullptr,
			CRYPTPROTECT_UI_FORBIDDEN, &protectedData)) return false;
		TArray<uint8_t> base64 = base64_encode(protectedData.pbData, protectedData.cbData);
		encoded.assign((const char*)base64.Data(), base64.Size() - 1);
		LocalFree(protectedData.pbData);
		return true;
#else
		(void)key;
		(void)encoded;
		return false;
#endif
	}

	bool UnprotectPrivateKey(const std::string& encoded, FString& key)
	{
#ifdef _WIN32
		if (encoded.empty() || encoded.size() % 4 != 0) return false;
		size_t decodedLength = (encoded.size() / 4) * 3;
		if (encoded.back() == '=') --decodedLength;
		if (encoded.size() > 1 && encoded[encoded.size() - 2] == '=') --decodedLength;
		if (decodedLength == 0 || decodedLength > 8192 || decodedLength > MAXDWORD) return false;
		TArray<uint8_t> encrypted;
		encrypted.Resize((unsigned)decodedLength);
		base64_decode(encrypted.Data(), decodedLength, encoded.c_str());
		DATA_BLOB input{(DWORD)decodedLength, encrypted.Data()};
		DATA_BLOB entropy{(DWORD)(sizeof(VaultPassword) - 1), (BYTE*)VaultPassword};
		DATA_BLOB plain{};
		if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain))
			return false;
		if (plain.cbData == 0 || plain.cbData > 4096)
		{
			SecureZeroMemory(plain.pbData, plain.cbData);
			LocalFree(plain.pbData);
			return false;
		}
		key = FString((const char*)plain.pbData, plain.cbData);
		SecureZeroMemory(plain.pbData, plain.cbData);
		LocalFree(plain.pbData);
		return true;
#else
		(void)encoded;
		(void)key;
		return false;
#endif
	}

	bool LoadPrivateKey()
	{
		if (PrivateKeyLoaded) return PrivateKeyAvailable;
		PrivateKeyLoaded = true;
		std::string encoded;
		if (ReadPrivateKeyVault(encoded) && UnprotectPrivateKey(encoded, PrivateKeyValue))
			PrivateKeyAvailable = true;
		return PrivateKeyAvailable;
	}

	enum class ERequestType { Authenticate, Unlock, FetchTrophies };

	struct FRequest
	{
		ERequestType Type;
		int TrophyId = 0;
		int GameId = 0;
		std::string Username;
		std::string UserToken;
		std::string PrivateKey;
	};

	struct FApiTrophy
	{
		int Id = 0;
		std::string Title;
		std::string Description;
		std::string Difficulty;
		bool Achieved = false;
	};

	struct FResult
	{
		ERequestType Type;
		int TrophyId = 0;
		bool Success = false;
		std::string Error;
		std::string TrophyTitle;
		std::vector<FApiTrophy> Trophies;
	};

	std::string UrlEncode(const std::string& value)
	{
		static constexpr char Hex[] = "0123456789ABCDEF";
		std::string result;
		for (unsigned char c : value)
		{
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~')
			{
				result.push_back((char)c);
			}
			else
			{
				result.push_back('%');
				result.push_back(Hex[c >> 4]);
				result.push_back(Hex[c & 15]);
			}
		}
		return result;
	}

	std::string Md5Hex(const std::string& text)
	{
		MD5Context context;
		context.Update(reinterpret_cast<const uint8_t*>(text.data()), (unsigned)text.size());
		uint8_t digest[16];
		context.Final(digest);
		static constexpr char Hex[] = "0123456789abcdef";
		std::string result;
		result.reserve(32);
		for (uint8_t byte : digest)
		{
			result.push_back(Hex[byte >> 4]);
			result.push_back(Hex[byte & 15]);
		}
		return result;
	}

	using FParams = std::vector<std::pair<std::string, std::string>>;

	std::string EncodeParams(const FParams& params)
	{
		std::string encoded;
		for (size_t i = 0; i < params.size(); ++i)
		{
			if (i) encoded.push_back('&');
			encoded += UrlEncode(params[i].first);
			encoded.push_back('=');
			encoded += UrlEncode(params[i].second);
		}
		return encoded;
	}

	size_t ReceiveBody(char* data, size_t size, size_t count, void* userData)
	{
		const size_t bytes = size * count;
		static_cast<std::string*>(userData)->append(data, bytes);
		return bytes;
	}

	bool ReadString(const rapidjson::Value& object, const char* key, std::string& out)
	{
		if (!object.IsObject() || !object.HasMember(key)) return false;
		const auto& value = object[key];
		if (!value.IsString()) return false;
		out.assign(value.GetString(), value.GetStringLength());
		return true;
	}

	bool ReadSuccess(const rapidjson::Value& response)
	{
		if (!response.IsObject() || !response.HasMember("success")) return false;
		const auto& value = response["success"];
		if (value.IsBool()) return value.GetBool();
		return value.IsString() && strcmp(value.GetString(), "true") == 0;
	}

	bool PerformRequest(const FRequest& request, const std::string& endpoint, FParams queryParams,
		FParams postParams, bool usePost,
		std::string& responseBody, std::string& error)
	{
		queryParams.emplace_back("game_id", std::to_string(request.GameId));
		if (!request.Username.empty()) queryParams.emplace_back("username", request.Username);
		if (!request.UserToken.empty())
		{
			auto& destination = usePost ? postParams : queryParams;
			destination.emplace_back("user_token", request.UserToken);
		}
		const std::string baseUrl = std::string(ApiRoot) + endpoint + "/?" + EncodeParams(queryParams);
		std::string signatureInput = baseUrl;
		if (usePost)
		{
			auto sorted = postParams;
			std::sort(sorted.begin(), sorted.end(), [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });
			for (const auto& item : sorted) signatureInput += item.first + item.second;
		}
		signatureInput += request.PrivateKey;
		const std::string signature = Md5Hex(signatureInput);
		const std::string url = baseUrl + "&signature=" + signature;
		const std::string postBody = EncodeParams(postParams);

		CURL* curl = curl_easy_init();
		if (!curl)
		{
			error = "curl_easy_init failed";
			return false;
		}

		char errorBuffer[CURL_ERROR_SIZE] = {};
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorBuffer);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		if (usePost)
		{
			curl_easy_setopt(curl, CURLOPT_POST, 1L);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postBody.c_str());
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)postBody.size());
		}
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "UZDoom GameJolt API/1.0");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ReceiveBody);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8L);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

		const CURLcode status = curl_easy_perform(curl);
		if (status != CURLE_OK)
		{
			error = errorBuffer[0] ? errorBuffer : curl_easy_strerror(status);
			curl_easy_cleanup(curl);
			return false;
		}
		curl_easy_cleanup(curl);
		return true;
	}

	bool ParseResponse(const std::string& body, rapidjson::Document& document, std::string& error)
	{
		document.Parse(body.c_str(), body.size());
		if (document.HasParseError() || !document.IsObject() || !document.HasMember("response") || !document["response"].IsObject())
		{
			error = "Game Jolt returned invalid JSON";
			return false;
		}
		const auto& response = document["response"];
		if (!ReadSuccess(response))
		{
			ReadString(response, "message", error);
			if (error.empty()) error = "Game Jolt rejected the request";
			return false;
		}
		return true;
	}

	FResult Execute(const FRequest& request)
	{
		FResult result;
		result.Type = request.Type;
		result.TrophyId = request.TrophyId;
		std::string body;
		std::string error;
		rapidjson::Document document;

		if (request.Type == ERequestType::Authenticate)
		{
			if (!PerformRequest(request, "users/auth", {}, {}, false, body, error) || !ParseResponse(body, document, error))
			{
				result.Error = std::move(error);
				return result;
			}
			result.Success = true;
			return result;
		}

		// Game Jolt calls authenticate the user and sign every operation. Keeping the
		// validation in this worker also prevents credentials from touching the main loop.
		if (!PerformRequest(request, "users/auth", {}, {}, false, body, error) || !ParseResponse(body, document, error))
		{
			result.Error = std::move(error);
			return result;
		}

		body.clear();
		if (request.Type == ERequestType::Unlock)
		{
			if (!PerformRequest(request, "trophies/add-achieved", {}, {{"trophy_id", std::to_string(request.TrophyId)}}, true, body, error) ||
				!ParseResponse(body, document, error))
			{
				result.Error = std::move(error);
				return result;
			}
			result.Success = true;
			if (document["response"].HasMember("trophy"))
				ReadString(document["response"]["trophy"], "title", result.TrophyTitle);
			return result;
		}

		if (!PerformRequest(request, "trophies", {}, {}, false, body, error) || !ParseResponse(body, document, error))
		{
			result.Error = std::move(error);
			return result;
		}
		const auto& response = document["response"];
		if (response.HasMember("trophies") && response["trophies"].IsArray())
		{
			for (const auto& item : response["trophies"].GetArray())
			{
				if (!item.IsObject() || !item.HasMember("id") || !item["id"].IsInt()) continue;
				FApiTrophy trophy;
				trophy.Id = item["id"].GetInt();
				ReadString(item, "title", trophy.Title);
				ReadString(item, "description", trophy.Description);
				ReadString(item, "difficulty", trophy.Difficulty);
				if (item.HasMember("achieved"))
				{
					const auto& achieved = item["achieved"];
					trophy.Achieved = !achieved.IsNull() && !(achieved.IsBool() && !achieved.GetBool()) &&
						!(achieved.IsString() && strcmp(achieved.GetString(), "false") == 0);
				}
				result.Trophies.push_back(std::move(trophy));
			}
		}
		result.Success = true;
		return result;
	}

	class FGameJoltService
	{
	public:
		~FGameJoltService()
		{
			{
				std::lock_guard<std::mutex> guard(Lock);
				Stopping = true;
				Requests.clear();
			}
			Wake.notify_all();
			if (Worker.joinable()) Worker.join();
		}

		bool Start()
		{
			if (Started) return true;
			if (!LoadCurl() || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return false;
			Started = true;
			Worker = std::thread([this] { Run(); });
			return true;
		}

		bool Queue(ERequestType type, int trophyId = 0)
		{
			if (!LoadPrivateKey()) return false;
			if (!Start()) return false;
			FRequest request;
			request.Type = type;
			request.TrophyId = trophyId;
			request.GameId = gamejolt_game_id;
			request.Username = *gamejolt_username;
			request.UserToken = *gamejolt_usertoken;
			request.PrivateKey = PrivateKeyValue.GetChars();
			if (request.GameId <= 0 || request.Username.empty() || request.UserToken.empty() || request.PrivateKey.empty()) return false;
			{
				std::lock_guard<std::mutex> guard(Lock);
				Requests.push_back(std::move(request));
			}
			Wake.notify_one();
			return true;
		}

		void QueuePendingUnlock(int trophyId)
		{
			if (InFlight.count(trophyId)) return;
			InFlight.insert(trophyId);
			if (!Queue(ERequestType::Unlock, trophyId)) InFlight.erase(trophyId);
		}

		std::vector<FResult> TakeResults()
		{
			std::lock_guard<std::mutex> guard(Lock);
			std::vector<FResult> result;
			result.reserve(Results.size());
			while (!Results.empty())
			{
				result.push_back(std::move(Results.front()));
				Results.pop_front();
			}
			return result;
		}

		bool Authenticated = false;
		bool PendingLoaded = false;
		std::set<int> Pending;
		std::set<int> Achieved;
		TArray<FGJTrophy> Trophies;
		std::set<int> InFlight;
		std::map<int, int> RetryCount;
		std::map<int, Clock::time_point> RetryAt;

	private:
		void Run()
		{
			while (true)
			{
				FRequest request;
				{
					std::unique_lock<std::mutex> guard(Lock);
					Wake.wait(guard, [this] { return Stopping || !Requests.empty(); });
					if (Stopping && Requests.empty()) return;
					request = std::move(Requests.front());
					Requests.pop_front();
				}
				FResult result = Execute(request);
				{
					std::lock_guard<std::mutex> guard(Lock);
					Results.push_back(std::move(result));
				}
			}
		}

		std::mutex Lock;
		std::condition_variable Wake;
		std::deque<FRequest> Requests;
		std::deque<FResult> Results;
		std::thread Worker;
		bool Started = false;
		bool Stopping = false;
	};

	FGameJoltService& Service()
	{
		static FGameJoltService instance;
		return instance;
	}

	void PersistPending(const FGameJoltService& service)
	{
		std::string ids;
		for (int id : service.Pending)
		{
			if (!ids.empty()) ids.push_back(',');
			ids += std::to_string(id);
		}
		cvar_forceset("gamejolt_pending_trophies", ids.c_str());
	}

	void LoadPending(FGameJoltService& service)
	{
		if (service.PendingLoaded) return;
		service.PendingLoaded = true;
		std::string value = *gamejolt_pending_trophies;
		size_t start = 0;
		while (start < value.size())
		{
			size_t end = value.find(',', start);
			if (end == std::string::npos) end = value.size();
			try
			{
				int id = std::stoi(value.substr(start, end - start));
				if (id > 0) service.Pending.insert(id);
			}
			catch (...) {}
			start = end + 1;
		}
	}

	void ShowUnlocked(const std::string& title, int trophyId)
	{
		FString text;
		if (!title.empty()) text.Format("Achievement unlocked: %s", title.c_str());
		else text.Format("Achievement unlocked: #%d", trophyId);
		if (StatusBar)
			StatusBar->AttachMessage(Create<DHUDMessageFadeOut>(nullptr, text.GetChars(),
				1.5f, 0.80f, 0, 0, CR_GOLD, 4.f, 0.5f), 0x474A0000u | (uint32_t)trophyId);
		else
			Printf(PRINT_NOTIFY, "%s\n", text.GetChars());
	}
}

void GameJolt_Authenticate()
{
	Service().Authenticated = false;
	const char* username = *gamejolt_username;
	const char* userToken = *gamejolt_usertoken;
	if (gamejolt_game_id <= 0 || !username || !username[0] || !userToken || !userToken[0])
	{
		Printf(PRINT_NOTIFY, "Game Jolt login was not started. Set the game ID, username, and Game Token.\n");
		return;
	}
	if (!LoadPrivateKey())
	{
		Printf(PRINT_NOTIFY, "Game Jolt login was not started. Enter the game's private key in the Game Jolt menu.\n");
		return;
	}
	if (!Service().Queue(ERequestType::Authenticate))
		Printf(PRINT_NOTIFY, "Game Jolt login could not start the HTTP client. Check the libcurl setup.\n");
}

bool GameJolt_SetPrivateKey(const char* key)
{
	std::string encoded;
	if (!key || !ProtectPrivateKey(key, encoded) || !WritePrivateKeyVault(encoded))
	{
		Printf(PRINT_NOTIFY, "Game Jolt private key could not be encrypted and saved on this platform.\n");
		return false;
	}
	PrivateKeyValue = key;
	PrivateKeyLoaded = true;
	PrivateKeyAvailable = true;
	Printf(PRINT_NOTIFY, "Game Jolt private key encrypted and saved to the user config folder.\n");
	return true;
}

bool GameJolt_HasPrivateKey()
{
	return LoadPrivateKey();
}

void GameJolt_UnlockTrophy(int trophyId)
{
	if (trophyId <= 0) return;
	auto& service = Service();
	LoadPending(service);
	if (service.Achieved.count(trophyId) || service.Pending.count(trophyId)) return;
	service.Pending.insert(trophyId);
	PersistPending(service);
	service.RetryAt[trophyId] = Clock::now();
	service.QueuePendingUnlock(trophyId);
}

void GameJolt_FetchTrophies()
{
	Service().Queue(ERequestType::FetchTrophies);
}

bool GameJolt_IsAuthenticated()
{
	return Service().Authenticated;
}

bool GameJolt_IsTrophyAchieved(int trophyId)
{
	return Service().Achieved.count(trophyId) != 0;
}

const TArray<FGJTrophy>& GameJolt_GetTrophies()
{
	return Service().Trophies;
}

void GameJolt_Tick()
{
	auto& service = Service();
	LoadPending(service);
	for (int trophyId : service.Pending)
	{
		if (service.InFlight.count(trophyId)) continue;
		auto it = service.RetryAt.find(trophyId);
		if (it != service.RetryAt.end() && it->second > Clock::now()) continue;
		service.QueuePendingUnlock(trophyId);
			if (!service.InFlight.count(trophyId))
				service.RetryAt[trophyId] = Clock::now() + std::chrono::seconds(30);
	}

	for (auto& result : service.TakeResults())
	{
		if (result.Type == ERequestType::Authenticate)
		{
			service.Authenticated = result.Success;
			if (result.Success)
				Printf(PRINT_NOTIFY, "Game Jolt authentication successful.\n");
			else
				Printf(PRINT_NOTIFY, "Game Jolt authentication failed: %s\n", result.Error.c_str());
			continue;
		}
		if (result.Type == ERequestType::FetchTrophies)
		{
			if (result.Success)
			{
				service.Trophies.Clear();
				service.Achieved.clear();
				for (const auto& item : result.Trophies)
				{
					FGJTrophy trophy;
					trophy.Id = item.Id;
					trophy.Title = item.Title.c_str();
					trophy.Description = item.Description.c_str();
					trophy.Difficulty = item.Difficulty.c_str();
					trophy.Achieved = item.Achieved;
					service.Trophies.Push(trophy);
					if (item.Achieved) service.Achieved.insert(item.Id);
				}
			}
			continue;
		}

		service.InFlight.erase(result.TrophyId);
		if (result.Success)
		{
			service.Pending.erase(result.TrophyId);
			service.Achieved.insert(result.TrophyId);
			service.RetryCount.erase(result.TrophyId);
			service.RetryAt.erase(result.TrophyId);
			PersistPending(service);
			ShowUnlocked(result.TrophyTitle, result.TrophyId);
		}
		else
		{
			int& attempts = service.RetryCount[result.TrophyId];
			attempts = std::min(attempts + 1, 8);
			const int delaySeconds = std::min(5 << (attempts - 1), 300);
			service.RetryAt[result.TrophyId] = Clock::now() + std::chrono::seconds(delaySeconds);
			DPrintf(DMSG_WARNING, "Game Jolt trophy %d will retry in %d seconds: %s\n",
				result.TrophyId, delaySeconds, result.Error.c_str());
		}
	}
}
