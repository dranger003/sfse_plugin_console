#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <fstream>
#include <format>
#include <chrono>

#include "sfse/PluginAPI.h"

#include "sfse_common/sfse_version.h"
#include "sfse_common/Relocation.h"
#include "sfse_common/BranchTrampoline.h"
#include "sfse_common/SafeWrite.h"

#include "xbyak/xbyak/xbyak.h"

#pragma comment(lib, "sfse_common")

// Globals

static const PluginHandle g_PluginHandle = static_cast<PluginHandle>(0);

static const SFSEInterface* g_SFSEInterface = nullptr;
static const SFSEMessagingInterface* g_SFSEMessagingInterface = nullptr;

static std::ofstream g_Log;

static BranchTrampoline g_Trampoline;

// Utils / Logging

static std::string _TS() {
	auto now = std::chrono::system_clock::now();

	auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
	auto epoch = now_ms.time_since_epoch();
	auto value = std::chrono::duration_cast<std::chrono::milliseconds>(epoch);
	auto ms = value.count() % 1000;
	auto now_time_t = std::chrono::system_clock::to_time_t(now);

	std::tm now_tm;
	localtime_s(&now_tm, &now_time_t);

	return std::format("{:4}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", now_tm.tm_year + 1900, now_tm.tm_mon + 1, now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec, ms);
}

template<typename... Args>
static void _LOG(const std::string& fmt, Args&&... args) {
	auto message = std::vformat(fmt, std::make_format_args(std::forward<Args>(args)...));
	g_Log << std::format("{}: {}", _TS(), message) << std::endl;
}

static void _LOGB(const char* message) {
	g_Log << message;
	g_Log.flush();
}

// Hooks / ConsoleOutputLine

struct hkConsoleOutputLine
{
	struct Asm : Xbyak::CodeGenerator {
		Asm() {
			Xbyak::Label label1;

			mov(ptr[rsp + 0x8], rbx);								// DSP/04/01/D | 48 89 5C 24 08                       | 48 89 5C 24 ??
			jmp(ptr[rip + label1]);

			L(label1);
			dq(RelocAddr<decltype(&Hook)>(0x02AE7C75 + 5).getUIntPtr()); // 0x02A44285
		}
	};

	static void Apply() {
		g_Trampoline.write5Branch(RelocAddr<uintptr_t>(0x02AE7C75).getUIntPtr(), (uintptr_t)&Hook); // 0x02A44285
	}

	static void Hook(void* unk1, void* unk2) {
		_Hook.getCode<decltype(&Hook)>()(unk1, unk2);

		auto line = reinterpret_cast<const char*>(unk2);
		_LOGB(line);
	}

	static Asm _Hook;
};

hkConsoleOutputLine::Asm hkConsoleOutputLine::_Hook;

// SFSE Plugin Integration

static void SFSEPlugin_EventCallback(SFSEMessagingInterface::Message* msg)
{
	if (msg->type == SFSEMessagingInterface::kMessage_PostLoad) {
		hkConsoleOutputLine::Apply();
	}
}

extern "C"
{
	__declspec(dllexport) SFSEPluginVersionData SFSEPlugin_Version = {
		SFSEPluginVersionData::kVersion, 1, "Console Hooks", "stonegdi", 0, 0, { RUNTIME_VERSION_1_14_70, 0 }, 0, 0, 0,
	};

	__declspec(dllexport) bool SFSEPlugin_Preload(const SFSEInterface* sfse) {
		return true;
	}

	__declspec(dllexport) bool SFSEPlugin_Load(const SFSEInterface* sfse) {
		g_SFSEInterface = sfse;
		g_SFSEMessagingInterface = (SFSEMessagingInterface*)g_SFSEInterface->QueryInterface(kInterface_Messaging);
		g_SFSEMessagingInterface->RegisterListener(g_PluginHandle, "SFSE", &SFSEPlugin_EventCallback);

		g_Trampoline.create(64 * 1024);
		g_Log = std::ofstream("Data\\SFSE\\plugins\\sfse_plugin_console.log", std::ios::out);

		return true;
	}
}

// DllMain

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	return TRUE;
}
