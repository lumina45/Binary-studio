import { PluginScript, BinaryMetadata } from './types';

export const DEFAULT_PLUGINS: PluginScript[] = [
  {
    id: "scan_rwx",
    name: "Identify RWX Memory Allocations",
    description: "Iterates through imported symbols and assembly opcodes to detect direct memory configuration overrides like VirtualAlloc (PAGE_EXECUTE_READWRITE) characteristic of packers & beacons.",
    author: "Malware Labs Research",
    version: "1.2.0",
    targetTrigger: "onImportParse",
    code: `// Identify RWX memory segments dynamically
const suspiciousImports = binary.imports.filter(imp => imp.isSuspicious);
print("Scanning imports size: " + binary.imports.length);
print("Suspicious API handles found: " + suspiciousImports.length);

suspiciousImports.forEach(imp => {
  print(\`[WARNING] Verified Import: \${imp.library}!\${imp.name} at \${imp.address} -> \${imp.reason ?? 'Direct dynamic linkage'}\`);
});

const rwxSections = binary.sections.filter(sec => sec.entropy > 7.0);
if (rwxSections.length > 0) {
  print("[MATCH] Found potential packer / encrypted binary sections: " + rwxSections.map(s => s.name).join(', '));
} else {
  print("[INFO] Section entropy thresholds appear normal.");
}
`,
    isDefault: true
  },
  {
    id: "strings_c2_scanner",
    name: "C2 Callback Domain Searcher",
    description: "Evaluates extracted strings for pattern matches representing command and control channels, dynamic web APIs, or URL endpoints.",
    author: "NetSec Ops",
    version: "2.0.4",
    targetTrigger: "onStringSearch",
    code: `// Domain and host scanner plugin
print("Scanning file strings index: " + binary.strings.length + " entries");
let alertIndex = 0;

binary.strings.forEach(str => {
  if (str.value.startsWith("http") || str.value.includes("/") || str.value.includes(".net") || str.value.includes(".com")) {
    alertIndex++;
    print(\`[ALERT #\${alertIndex}] Found suspicious host/callback string: "\${str.value}" at virtual address \${str.address}\`);
    if (str.context) {
      print(\`      Context analysis: \${str.context}\`);
    }
  }
});

if (alertIndex === 0) {
  print("[OK] No suspicious active host URL patterns matched in strings pool.");
}
`,
    isDefault: true
  },
  {
    id: "opcode_nop_detector",
    name: "NOP Sled & Jump Target Finder",
    description: "Analyzes disassembler rows to detect long consecutive NOP lines ('90') often indicating shellcode buffer pads or debugger trap configurations.",
    author: "Anti-Evasion Corp",
    version: "1.0.1",
    targetTrigger: "onAnalyze",
    code: `// Scan Assembly lines for shellcode artifacts
print("Parsing linear instructions sequence starting at " + binary.entryPoint);
let nopCount = 0;
let totalLines = binary.assembly.length;

binary.assembly.forEach((line, index) => {
  if (line.opcodes.toLowerCase().includes("90") || line.mnemonic === "nop") {
    nopCount++;
    print(\`[INFO] Line \${index}: NOP opcode spotted at \${line.address} (\${line.opcodes})\`);
  }
  if (line.mnemonic === "jmp") {
    print(\`[CALL-MAP] Jump destination targeted at address \${line.address} to \${line.operands}\`);
  }
});

print(\`---------------------------------------
Analysis result: \${nopCount} NOPs found out of \${totalLines} instructions. Ratio: \${((nopCount/totalLines)*100).toFixed(2)}%\`);
`,
    isDefault: true
  },
  {
    id: "custom_sandboxed_script",
    name: "Custom Decompiler Modifier",
    description: "Create your own binary signature scanners. Target, inspect, and isolate malicious routines programmatically.",
    author: "Local Analyst",
    version: "1.0.0",
    targetTrigger: "onDecompile",
    code: `// Custom user evaluation script
print("Analyzing decompiled routines for binary: " + binary.fileName);
binary.decompiledFunctions.forEach(fn => {
  print(\`Found routine '\${fn.name}' returning \${fn.returnType} (\${fn.arguments.join(', ')}) at \${fn.address}\`);
  const lines = fn.body.length;
  print(\`   Size: \${lines} reconstructed lines of code.\`);
  
  // Search for registry modifications
  const modifiesRegistry = fn.body.some(line => line.includes("Reg") || line.includes("Registry") || line.includes("Registry"));
  if (modifiesRegistry) {
    print(\`   [STATE CHANGE] Warning: this routine modifies Registry parameters!\`);
  }
});
`,
    isDefault: false
  }
];

// Helper to execute client side simulated scripts safely
export function runSandboxPlugin(plugin: PluginScript, binary: BinaryMetadata, appendLog: (text: string) => void): void {
  appendLog(`>>> Running Plugin "${plugin.name}" [v${plugin.version}] by ${plugin.author}...`);
  
  // Prepare a custom console log mock
  let outputBuffer: string[] = [];
  const print = (text: string) => {
    outputBuffer.push(text);
  };

  try {
    // We bind variables in a function mapping
    const execFunction = new Function('binary', 'print', plugin.code);
    execFunction(binary, print);
    
    if (outputBuffer.length === 0) {
      appendLog("Plugin executed successfully with empty stdout.");
    } else {
      outputBuffer.forEach(line => appendLog(line));
    }
    appendLog(`>>> End of Execution for "${plugin.name}".\n`);
  } catch (err: any) {
    appendLog(`[ERROR] Plugin runtime failure: ${err?.message ?? err}`);
    appendLog("Please double check script syntax and variables accessed.");
  }
}
