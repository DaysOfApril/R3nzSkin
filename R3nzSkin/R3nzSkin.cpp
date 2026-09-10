#pragma warning(disable : 6387 4715)

#include <Windows.h>
#include <clocale>
#include <chrono>
#include <thread>

#include "CheatManager.hpp"

#include "Config.hpp"
#include "Hooks.hpp"
#include "Memory.hpp"

#include "SDK/GameState.hpp"

bool WINAPI HideThread(const HANDLE hThread) noexcept
{
	__try {
		using FnSetInformationThread = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, UINT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
		const auto NtSetInformationThread{ reinterpret_cast<FnSetInformationThread>(::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread")) };

		if (!NtSetInformationThread)
			return false;

		if (const auto status{ NtSetInformationThread(hThread, 0x11u, nullptr, 0ul) }; status == 0x00000000)
			return true;
	} __except (TRUE) {
		return false;
	}
	return false;
}

__declspec(safebuffers) static void WINAPI DllAttach([[maybe_unused]] LPVOID lp) noexcept
{
	using namespace std::chrono_literals;

	cheatManager.start();
	if (HideThread(::GetCurrentThread()))
		cheatManager.logger->addLog("Thread Hidden!\n");

	cheatManager.memory->Search(true);
	while (true) {
		std::this_thread::sleep_for(1s);
		
		if (!cheatManager.memory->client)
			cheatManager.memory->Search(true);
		else if (cheatManager.memory->client->game_state == GGameState_s::Running)
			break;
	}
	cheatManager.logger->addLog("GameClient found!\n");
	
	std::this_thread::sleep_for(500ms);
	cheatManager.memory->Search(false);
	cheatManager.logger->addLog("All offsets found!\n");
	std::this_thread::sleep_for(500ms);

	cheatManager.config->init();
	cheatManager.config->load();
	cheatManager.gui->is_open = cheatManager.config->isOpen;
	cheatManager.logger->addLog("CFG loaded!\n");
	
	cheatManager.hooks->install();
		
	while (cheatManager.cheatState)
		std::this_thread::sleep_for(250ms);

	::ExitProcess(0u);
}

__declspec(safebuffers) BOOL APIENTRY DllMain(const HMODULE hModule, const DWORD reason, [[maybe_unused]] LPVOID reserved)
{
	DisableThreadLibraryCalls(hModule);

	if (reason != DLL_PROCESS_ATTACH)
		return FALSE;

	HideThread(hModule);
	std::setlocale(LC_ALL, ".utf8");

	::_beginthreadex(nullptr, 0u, reinterpret_cast<_beginthreadex_proc_type>(DllAttach), nullptr, 0u, nullptr);
	::CloseHandle(hModule);
	return TRUE;
}

// ---------------------------------------------------------------------------
// The launcher bundled with the releases injects R3nzSkin.dll with
// SetWindowsHookEx: it resolves this symbol from the DLL and hands the address
// to SetWindowsHookEx, which makes Windows map the DLL into the game process.
//
// The published DLL exports exactly this one symbol ("NextHook"). The open-source
// tree does not, so a DLL built from this repository has an *empty* export table,
// GetProcAddress() returns nullptr, the hook is never installed and the launcher
// silently reports "Not Injected". Keep this name and signature exactly as-is.
//
// The body only has to be a valid hook procedure -- the real work happens in
// DllMain() above, which Windows calls when the DLL gets mapped into the game.
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport) LRESULT CALLBACK NextHook(const int code, const WPARAM wParam, const LPARAM lParam) noexcept
{
	return ::CallNextHookEx(nullptr, code, wParam, lParam);
}
