#include "app.h"
#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include <d3d11.h>
#include <shellapi.h>
#include <wrl/client.h>
#include <cstdio>
#include <cwchar>
#include <stdexcept>
#include <string>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace
{
	using Microsoft::WRL::ComPtr;
	struct window_state
	{
		pd_gui::app* application = nullptr;
		UINT width = 0;
		UINT height = 0;
		float scale = 1.0f;
		bool close_pending = false;
	};

	LRESULT WINAPI window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
	{
		if (message == WM_NCCREATE)
		{
			const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
			SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
		}
		auto* state = reinterpret_cast<window_state*>(GetWindowLongPtrW(window, GWLP_USERDATA));
		if (ImGui_ImplWin32_WndProcHandler(window, message, wparam, lparam)) return TRUE;
		switch (message)
		{
		case WM_SIZE:
			if (state && wparam != SIZE_MINIMIZED)
			{
				state->width = LOWORD(lparam);
				state->height = HIWORD(lparam);
			}
			return 0;
		case WM_GETMINMAXINFO:
			if (state)
			{
				auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
				limits->ptMinTrackSize = {static_cast<LONG>(850 * state->scale), static_cast<LONG>(650 * state->scale)};
			}
			return 0;
		case WM_DPICHANGED:
		{
			if (state) state->scale = HIWORD(wparam) / 96.0f;
			const auto* rectangle = reinterpret_cast<const RECT*>(lparam);
			SetWindowPos(window, nullptr, rectangle->left, rectangle->top,
				rectangle->right - rectangle->left, rectangle->bottom - rectangle->top,
				SWP_NOZORDER | SWP_NOACTIVATE);
			return 0;
		}
		case WM_SYSCOMMAND:
			if ((wparam & 0xfff0) == SC_KEYMENU) return 0;
			break;
		case WM_CLOSE:
			if (state && state->application)
			{
				state->application->request_close();
				state->close_pending = true;
				if (IsIconic(window)) ShowWindow(window, SW_RESTORE);
				SetForegroundWindow(window);
			}
			else DestroyWindow(window);
			return 0;
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
		}
		return DefWindowProcW(window, message, wparam, lparam);
	}

	void check(HRESULT result, const char* operation)
	{
		if (FAILED(result))
			throw std::runtime_error(std::string(operation) + " (HRESULT " + std::to_string(static_cast<unsigned long>(result)) + ").");
	}

	class graphics
	{
	public:
		ComPtr<ID3D11Device> device;
		ComPtr<ID3D11DeviceContext> context;
		ComPtr<IDXGISwapChain> swap_chain;
		ComPtr<ID3D11RenderTargetView> target;
		bool win32_initialized = false;
		bool dx11_initialized = false;

		explicit graphics(HWND window)
		{
			DXGI_SWAP_CHAIN_DESC description{};
			description.BufferCount = 2;
			description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
			description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
			description.OutputWindow = window;
			description.SampleDesc.Count = 1;
			description.Windowed = TRUE;
			description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
			const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
			auto create = [&](D3D_DRIVER_TYPE driver) {
				return D3D11CreateDeviceAndSwapChain(nullptr, driver, nullptr, 0, levels, ARRAYSIZE(levels),
					D3D11_SDK_VERSION, &description, swap_chain.ReleaseAndGetAddressOf(), device.ReleaseAndGetAddressOf(),
					nullptr, context.ReleaseAndGetAddressOf());
			};
			HRESULT result = create(D3D_DRIVER_TYPE_HARDWARE);
			if (FAILED(result)) result = create(D3D_DRIVER_TYPE_WARP);
			check(result, "Cannot initialize DirectX 11 (including the software renderer)");
			create_target();
		}

		void create_target()
		{
			ComPtr<ID3D11Texture2D> buffer;
			check(swap_chain->GetBuffer(0, IID_PPV_ARGS(buffer.GetAddressOf())), "Cannot get display buffer");
			check(device->CreateRenderTargetView(buffer.Get(), nullptr, target.ReleaseAndGetAddressOf()), "Cannot create render target");
		}

		void resize(UINT width, UINT height)
		{
			context->OMSetRenderTargets(0, nullptr, nullptr);
			target.Reset();
			check(swap_chain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0), "Cannot resize display buffers");
			create_target();
		}

		~graphics()
		{
			if (dx11_initialized) ImGui_ImplDX11_Shutdown();
			if (win32_initialized) ImGui_ImplWin32_Shutdown();
		}
	};

	class imgui_context
	{
	public:
		imgui_context() { IMGUI_CHECKVERSION(); ImGui::CreateContext(); }
		~imgui_context() { ImGui::DestroyContext(); }
	};

	class native_window
	{
		HINSTANCE instance_;
		const wchar_t* class_name_ = L"ProcessDumpImGui";
	public:
		HWND handle = nullptr;
		native_window(HINSTANCE instance, window_state& state) : instance_(instance)
		{
			WNDCLASSEXW description{sizeof(description)};
			description.style = CS_CLASSDC;
			description.lpfnWndProc = window_proc;
			description.hInstance = instance;
			description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
			description.lpszClassName = class_name_;
			if (!RegisterClassExW(&description)) throw std::runtime_error("Cannot register the application window.");
			handle = CreateWindowExW(0, class_name_, L"Process Dump - Dear ImGui", WS_OVERLAPPEDWINDOW,
				CW_USEDEFAULT, CW_USEDEFAULT, static_cast<int>(1100 * state.scale), static_cast<int>(820 * state.scale),
				nullptr, nullptr, instance, &state);
			if (!handle)
			{
				UnregisterClassW(class_name_, instance_);
				throw std::runtime_error("Cannot create the application window.");
			}
		}
		~native_window()
		{
			if (IsWindow(handle)) DestroyWindow(handle);
			UnregisterClassW(class_name_, instance_);
		}
	};

	int run(HINSTANCE instance, int show, bool smoke_test)
	{
		ImGui_ImplWin32_EnableDpiAwareness();
		window_state state;
		state.scale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint({0, 0}, MONITOR_DEFAULTTOPRIMARY));
		native_window window(instance, state);
		imgui_context imgui;
		graphics renderer(window.handle);
		auto& io = ImGui::GetIO();
		io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
		io.IniFilename = nullptr;
		io.LogFilename = nullptr;
		ImFontConfig font;
		font.SizePixels = 16;
		wchar_t windows_directory[MAX_PATH];
		ImFont* ui_font = nullptr;
		const UINT length = GetWindowsDirectoryW(windows_directory, ARRAYSIZE(windows_directory));
		if (length && length < ARRAYSIZE(windows_directory))
		{
			const auto path = std::filesystem::path(windows_directory) / L"Fonts" / L"segoeui.ttf";
			if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
				ui_font = io.Fonts->AddFontFromFileTTF(pd_gui::to_utf8(path.wstring()).c_str(), 16, &font);
		}
		if (!ui_font) io.Fonts->AddFontDefault(&font);
		ImGui::StyleColorsDark();
		auto& style = ImGui::GetStyle();
		style.WindowPadding = ImVec2(18, 18);
		style.FramePadding = ImVec2(8, 6);
		style.ItemSpacing = ImVec2(10, 9);
		style.FrameRounding = 4;
		style.ChildRounding = 6;
		style.Colors[ImGuiCol_WindowBg] = ImVec4(0.055f, 0.065f, 0.08f, 1);
		style.Colors[ImGuiCol_Button] = ImVec4(0.10f, 0.32f, 0.30f, 1);
		style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.13f, 0.43f, 0.39f, 1);
		style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.12f, 0.50f, 0.44f, 1);
		style.ScaleAllSizes(state.scale);
		style.FontScaleDpi = state.scale;
		float previous_scale = state.scale;
		renderer.win32_initialized = ImGui_ImplWin32_Init(window.handle);
		if (!renderer.win32_initialized) throw std::runtime_error("Cannot initialize ImGui's Windows backend.");
		renderer.dx11_initialized = ImGui_ImplDX11_Init(renderer.device.Get(), renderer.context.Get());
		if (!renderer.dx11_initialized) throw std::runtime_error("Cannot initialize ImGui's DirectX backend.");
		pd_gui::app application(window.handle);
		state.application = &application;
		ShowWindow(window.handle, smoke_test ? SW_HIDE : show);
		UpdateWindow(window.handle);
		bool running = true;
		bool occluded = false;
		unsigned frames = 0;
		while (running)
		{
			MSG message;
			while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
			{
				TranslateMessage(&message);
				DispatchMessageW(&message);
				if (message.message == WM_QUIT) running = false;
			}
			if (!running) break;
			if (application.ready_to_close()) break;
			if (!smoke_test && !state.close_pending && (IsIconic(window.handle) || (occluded && renderer.swap_chain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)))
			{
				Sleep(30);
				continue;
			}
			if (state.width && state.height)
			{
				renderer.resize(state.width, state.height);
				state.width = state.height = 0;
			}
			if (state.scale != previous_scale)
			{
				style.ScaleAllSizes(state.scale / previous_scale);
				style.FontScaleDpi = state.scale;
				previous_scale = state.scale;
			}
			ImGui_ImplDX11_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();
			running = application.render();
			state.close_pending = false;
			ImGui::Render();
			ID3D11RenderTargetView* target = renderer.target.Get();
			renderer.context->OMSetRenderTargets(1, &target, nullptr);
			constexpr float clear[] = {0.055f, 0.065f, 0.08f, 1};
			renderer.context->ClearRenderTargetView(target, clear);
			ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
			const HRESULT presented = renderer.swap_chain->Present(1, 0);
			occluded = presented == DXGI_STATUS_OCCLUDED;
			check(presented, "Cannot present the application window");
			if (smoke_test && ++frames == 8) running = false;
		}
		state.application = nullptr;
		return 0;
	}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	int argc = 0;
	wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	const bool smoke_test = argv && argc == 2 && wcscmp(argv[1], L"--smoke-test") == 0;
	if (argv) LocalFree(argv);
	const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (FAILED(com))
	{
		if (smoke_test) fprintf(stderr, "Cannot initialize Windows COM services.\n");
		else MessageBoxW(nullptr, L"Cannot initialize Windows COM services.", L"Process Dump", MB_OK | MB_ICONERROR);
		return 1;
	}
	int result = 1;
	try { result = run(instance, show, smoke_test); }
	catch (const std::exception& error)
	{
		if (smoke_test)
		{
			fprintf(stderr, "%s\n", error.what());
			CoUninitialize();
			return 1;
		}
		// Error strings can include native paths; use the same checked UTF-8 conversion as the UI.
		try { MessageBoxW(nullptr, pd_gui::to_wide(error.what()).c_str(), L"Process Dump", MB_OK | MB_ICONERROR); }
		catch (...) { MessageBoxW(nullptr, L"An unexpected application error occurred.", L"Process Dump", MB_OK | MB_ICONERROR); }
	}
	CoUninitialize();
	return result;
}
