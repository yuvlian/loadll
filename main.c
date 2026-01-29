#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#define CONFIG_FILE "loadll.ini"

typedef struct {
    char exePath[MAX_PATH];
    char dllPath[MAX_PATH];
    char launchArgs[512];
    bool mustAdmin;
    char mode[16];
} Config;

void wait_exit() {
    printf("\nPress ENTER to exit...");
    getchar();
}

bool file_exists(const char* path) {
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

bool is_running_as_admin() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size)) {
            isElevated = elev.TokenIsElevated;
        }
    }

    if (hToken) CloseHandle(hToken);
    return isElevated;
}

void extract_exe_name(const char* path, char* out) {
    const char* lastBSlash = strrchr(path, '\\');
    const char* lastFSlash = strrchr(path, '/');
    const char* last = (lastFSlash > lastBSlash) ? lastFSlash : lastBSlash;
    strcpy(out, last ? last + 1 : path);
}

bool create_default_config() {
    FILE* f = fopen(CONFIG_FILE, "w");
    if (!f) {
        printf("Failed to create config file. Error: %s\n", strerror(errno));
        return false;
    }
    fprintf(f,
        "exePath=C:\\something\\Game.exe\n"
        "dllPath=C:\\whatever\\haxx.dll\n"
        "launchArgs=\n"
        "mustAdmin=true\n"
        "mode=loader\n"
    );
    fclose(f);
    return true;
}

bool load_config(Config* cfg) {
    if (!file_exists(CONFIG_FILE)) {
        printf("Config file is missing, initializing.\n");
        if (!create_default_config()) {
            printf("Default config file creation failed.\n");
        } else {
            printf("Config file created. Please edit %s and rerun.\n", CONFIG_FILE);
        }
        return false;
    }

    FILE* f = fopen(CONFIG_FILE, "r");
    if (!f) {
        printf("Failed to open config file. Error: %s\n", strerror(errno));
        return false;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == 0)
            continue;
        if (strncmp(line, "exePath=", 8) == 0)
            sscanf(line + 8, "%[^\n]", cfg->exePath);
        else if (strncmp(line, "dllPath=", 8) == 0)
            sscanf(line + 8, "%[^\n]", cfg->dllPath);
        else if (strncmp(line, "launchArgs=", 11) == 0)
            sscanf(line + 11, "%[^\n]", cfg->launchArgs);
        else if (strncmp(line, "mustAdmin=", 10) == 0)
            cfg->mustAdmin = strstr(line + 10, "true") != NULL;
        else if (strncmp(line, "mode=", 5) == 0)
            sscanf(line + 5, "%15s", cfg->mode);
    }

    fclose(f);

    if (strlen(cfg->exePath) == 0) {
        printf("Config validation failed: exePath is empty.\n");
        return false;
    }

    if (_stricmp(cfg->mode, "loader") == 0 && !file_exists(cfg->exePath)) {
        printf("Config validation failed: Executable not found at: %s\n", cfg->exePath);
        return false;
    }

    if (strlen(cfg->dllPath) == 0) {
        printf("Config validation failed: dllPath is empty.\n");
        return false;
    }

    if (!file_exists(cfg->dllPath)) {
        printf("Config validation failed: DLL not found at: %s\n", cfg->dllPath);
        return false;
    }

    if (strlen(cfg->mode) == 0) {
        printf("Config validation failed: mode is empty.\n");
        return false;
    }

    if (_stricmp(cfg->mode, "loader") != 0 && _stricmp(cfg->mode, "injector") != 0) {
        printf("Config validation failed: Invalid mode '%s'. Use 'loader' or 'injector'.\n", cfg->mode);
        return false;
    }

    return true;
}

DWORD get_pid_by_name(const char* exeName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create process snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    DWORD pid = 0;
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &procEntry)) {
        do {
            if (_stricmp(procEntry.szExeFile, exeName) == 0) {
                pid = procEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &procEntry));
    } else {
        printf("Failed to enumerate processes. Error: %lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
    return pid;
}

bool remote_thread_inject(HANDLE hProcess, const char* dllPath) {
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("Failed to get LoadLibraryA address. Error: %lu\n", GetLastError());
        return false;
    }

    size_t dPLen = strlen(dllPath) + 1;

    LPVOID vMem = VirtualAllocEx(hProcess, NULL, dPLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!vMem) {
        printf("Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(hProcess, vMem, dllPath, dPLen, NULL)) {
        printf("Failed to write DLL path to target process. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, vMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0, 
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, 
        vMem,
        0,
        NULL
    );

    if (!hThread) {
        printf("Failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, vMem, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, vMem, 0, MEM_RELEASE);

    return true;
}

int run_loader_mode(const Config* cfg) {
    STARTUPINFOA startupInfo = {0};
    PROCESS_INFORMATION procInfo = {0};
    startupInfo.cb = sizeof(startupInfo);

    char cmdLine[MAX_PATH + 512];
    if (strlen(cfg->launchArgs) > 0) {
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\" %s", cfg->exePath, cfg->launchArgs);
    } else {
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", cfg->exePath);
    }

    BOOL createProcOK = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        &procInfo
    );

    if (!createProcOK) {
        printf("Failed to create process. Error: %lu\n", GetLastError());
        return 1;
    }

    if (remote_thread_inject(procInfo.hProcess, cfg->dllPath)) {
        printf("Injection succeeded.\nResuming process.\n");
        ResumeThread(procInfo.hThread);
    } else {
        printf("Injection failed.\nTerminating process.\n");
        TerminateProcess(procInfo.hProcess, 1);
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);
        return 1;
    }

    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
    return 0;
}

int run_injector_mode(const Config* cfg) {
    char exeName[MAX_PATH];
    extract_exe_name(cfg->exePath, exeName);

    printf("Searching pid for: %s\n", exeName);
    DWORD pid = get_pid_by_name(exeName);
    if (!pid) {
        printf("Process not found. Is it running?\n");
        return 1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        printf("Failed to open process handle. Error: %lu\n", GetLastError());
        return 1;
    }

    if (remote_thread_inject(hProc, cfg->dllPath)) {
        printf("Injection succeeded.\n");
    } else {
        printf("Injection failed.\n");
        CloseHandle(hProc);
        return 1;
    }

    CloseHandle(hProc);
    return 0;
}

int main() {
    Config cfg = {0};

    if (!load_config(&cfg)) {
        wait_exit();
        return 1;
    }

    if (cfg.mustAdmin && !is_running_as_admin()) {
        printf("Please rerun as admin.\n");
        wait_exit();
        return 1;
    }

    int result = 0;

    if (_stricmp(cfg.mode, "loader") == 0) {
        result = run_loader_mode(&cfg);
    } else if (_stricmp(cfg.mode, "injector") == 0) {
        result = run_injector_mode(&cfg);
    }

    if (result != 0) wait_exit();
    return result;
}
