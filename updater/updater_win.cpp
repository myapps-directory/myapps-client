// ProgressBar.cpp

// Header required to help detect window version
#include <sdkddkver.h>

// Macro used to reduce namespace pollution
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Reference for various Win32 API functions and 
// structure declarations.
#include <Windows.h>

// Header needed for unicode adjustment support
#include <tchar.h>

#include <CommCtrl.h>

#pragma comment(lib, "comctl32.lib")

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "resource.h"
#include <thread>
#include <atomic>
#include <shellapi.h>
#include <mutex>

using namespace std;

#define ID_DEFAULTPROGRESSCTRL	401
#define ID_SMOOTHPROGRESSCTRL	402
#define ID_VERTICALPROGRESSCTRL	403

atomic<bool> running = true;

//
//
// WndProc - Window procedure
//
//
LRESULT
CALLBACK
WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_DESTROY:
		::PostQuitMessage(0);
		running = false;
		break;

	default:
		return ::DefWindowProc(hWnd, uMsg, wParam, lParam);
	}

	return 0;
}

//
//
// WinMain - Win32 application entry point.
//
//
int
APIENTRY
wWinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPWSTR lpCmdLine,
	int nShowCmd)
{
	int	 argc = 0;
	auto argv = CommandLineToArgvW(lpCmdLine, &argc);

	if (argc != 3) {
		int msgboxID = MessageBox(
			NULL,
			TEXT("Not propery called. There should be two arguments."),
			TEXT("Wrong program arguments"),
			MB_OK
		);
		return 0;
	}

	INITCOMMONCONTROLSEX iccex;
	iccex.dwSize = sizeof(iccex);
	iccex.dwICC = ICC_PROGRESS_CLASS;

	if (!InitCommonControlsEx(&iccex))
		return 1;

	// Setup window class attributes.
	WNDCLASSEX wcex;
	ZeroMemory(&wcex, sizeof(wcex));

	wcex.cbSize = sizeof(wcex);
	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpszClassName = TEXT("PROGRESSBARSAMPLE");
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW);
	wcex.hCursor = LoadCursor(hInstance, IDC_ARROW);
	wcex.lpfnWndProc = WndProc;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON));
	wcex.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON));

	// Register window and ensure registration success.
	if (!RegisterClassEx(&wcex))
		return 1;

	RECT rect;

	int width = 400;
	int height = 100;

	GetClientRect(GetDesktopWindow(), &rect);
	rect.left = (rect.right / 2) - (width / 2);
	rect.top = (rect.bottom / 2) - (height / 2);

	// Create the window.
	HWND hWnd = ::CreateWindowEx(
		0,
		TEXT("PROGRESSBARSAMPLE"),
		TEXT("MyApps.space update: copy installer"),
		//WS_OVERLAPPEDWINDOW,
		WS_OVERLAPPED | WS_SYSMENU,
		rect.left,
		rect.top,
		width,
		height,
		NULL,
		NULL,
		hInstance,
		NULL);

	// Validate window.
	if (!hWnd)
		return 1;


	HWND hDefaultProgressCtrl;

	GetClientRect(hWnd, &rect);
	// Create default progress bar.
	hDefaultProgressCtrl = ::CreateWindowEx(
		0,
		PROGRESS_CLASS,
		TEXT("Some text"),
		WS_CHILD | WS_VISIBLE,
		0,
		0,
		rect.right,
		rect.bottom,
		hWnd,
		(HMENU)ID_DEFAULTPROGRESSCTRL,
		hInstance,
		NULL);

	//::SendMessage(hDefaultProgressCtrl, PBM_SETPOS, (WPARAM)(INT)40, 0);

	auto thr = thread([](HWND hWnd, HWND hProgCtrl) {
		for (int i = 0; i < 100; ++i) {
			this_thread::sleep_for(chrono::milliseconds(100));
			::SendNotifyMessage(hProgCtrl, PBM_SETPOS, (WPARAM)(INT)(i + 1), 0);
			if (!running) break;
			if (i == 50) {
				SetWindowText(hWnd, TEXT("MyApps.space update: check installer"));
			}
			if (i == 99) {
				SetWindowText(hWnd, TEXT("MyApps.space update: start installer"));
			}
		}

		::PostMessage(hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
	}, hWnd, hDefaultProgressCtrl);

	// Display the window.
	::ShowWindow(hWnd, SW_SHOWDEFAULT);
	::UpdateWindow(hWnd);

	// Main message loop.
	MSG msg;
	while (::GetMessage(&msg, hWnd, 0, 0) > 0)
		::DispatchMessage(&msg);

	// Unregister window class, freeing the memory that was
	// previously allocated for this window.
	::UnregisterClass(wcex.lpszClassName, hInstance);
	thr.join();
	return (int)msg.wParam;
}