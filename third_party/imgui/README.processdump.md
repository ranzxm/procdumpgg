# Dear ImGui dependency

Unmodified Dear ImGui **v1.92.5**, pinned to upstream commit
`6d910d5487d11ca567b61c7824b0c78c569d62f0`:
https://github.com/ocornut/imgui/tree/6d910d5487d11ca567b61c7824b0c78c569d62f0

Only core source files, required internal/STB headers, the Win32/DirectX 11
backends, and the MIT license are vendored. Demo/example sources are omitted.
No network access or additional package manager is needed to build the GUI.

Keep the upstream license with redistributed GUI binaries. The GUI project copies
it to `ImGui-LICENSE.txt` in the output directory alongside the project license.
