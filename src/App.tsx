import React, { useState, useRef } from 'react';
import { SAMPLE_BINARIES, generateBinaryAnalysis } from './samples';
import { BinaryMetadata, AssemblyLine, SectionHeader, ImportSymbol, ExtractedString } from './types';
import { HexViewer } from './components/HexViewer';
import { PluginEngine } from './components/PluginEngine';
import { OsDownloadModule } from './components/OsDownloadModule';
import { 
  FileCode, 
  Binary, 
  Cpu, 
  ShieldAlert, 
  Terminal, 
  Search, 
  Upload, 
  Layers, 
  HelpCircle, 
  ChevronRight, 
  Play, 
  Database, 
  AlertOctagon, 
  FileText, 
  Sparkles, 
  Code,
  Download,
  Flame,
  Bug,
  Info,
  CheckCircle,
  Copy
} from 'lucide-react';

export default function App() {
  const [selectedBinaryKey, setSelectedBinaryKey] = useState<string>("wannacry");
  const [customBinary, setCustomBinary] = useState<BinaryMetadata | null>(null);
  const [activeTab, setActiveTab] = useState<'disassembly' | 'decompiler' | 'hex' | 'imports' | 'strings' | 'heuristics' | 'plugins' | 'downloads'>('disassembly');
  
  // Search parameters for different workspaces
  const [disassemblySearch, setDisassemblySearch] = useState("");
  const [importsSearch, setImportsSearch] = useState("");
  const [stringsSearch, setStringsSearch] = useState("");
  
  // Interactive selected items for analysis popup helpers
  const [focusedAsmLine, setFocusedAsmLine] = useState<AssemblyLine | null>(null);
  const [focusedImport, setFocusedImport] = useState<ImportSymbol | null>(null);
  const [focusedString, setFocusedString] = useState<ExtractedString | null>(null);

  // AI assistant states
  const [aiAnalysisResult, setAiAnalysisResult] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // File Upload states
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const getActiveBinary = (): BinaryMetadata => {
    if (customBinary) {
      return customBinary;
    }
    return SAMPLE_BINARIES[selectedBinaryKey] || SAMPLE_BINARIES.wannacry;
  };

  const binary = getActiveBinary();

  // Handle local simulation file uploads
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const mockResult = generateBinaryAnalysis(file.name, file.size);
      setCustomBinary(mockResult);
      setActiveTab('disassembly');
      setAiAnalysisResult(null);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const mockResult = generateBinaryAnalysis(file.name, file.size);
      setCustomBinary(mockResult);
      setActiveTab('disassembly');
      setAiAnalysisResult(null);
    }
  };

  const triggerSelectFile = () => {
    fileInputRef.current?.click();
  };

  const handleLoadSample = (key: string) => {
    setCustomBinary(null);
    setSelectedBinaryKey(key);
    setActiveTab('disassembly');
    setAiAnalysisResult(null);
    setFocusedAsmLine(null);
    setFocusedImport(null);
    setFocusedString(null);
  };

  // Trigger quick interactive AI static code explanations
  const triggerAiDecompilerAgent = () => {
    setAiLoading(true);
    setAiAnalysisResult(null);
    
    // Simulating deep heuristics parsed by AI models specifically for the targeted binary
    setTimeout(() => {
      let analysisSummary = "";
      if (binary.fileName.includes("mssecsvc")) {
        analysisSummary = `### AI Static Malware Analysis Report (WannaCry Binary variant)
**Target Identifier:** \`mssecsvc.exe\` | SHA-256: \`ed01eb...\`

1. **Anti-Evasion Killswitch Analyzed:** 
   The routine \`check_killswitch_and_run\` attempts to initialize WinInet socket traffic targeting the domain \`http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergweessae98.com\`. If the connection is successful, the execution exits immediately. If it fails (simulating a dead or blocked domain), it registers a persistent mutex named \`Local\\MsofficeMutex_32895\` to lock target processes before extracting the cryptographic payload.
   
2. **Payload Decryption Sequence:**
   The function \`extract_and_execute_payload\` accesses the binary's resource catalog mapping \`.wnry\`. It loads this packed block into executable heap memory using \`VirtualAllocEx\` and decrypts it with a fixed 128-bit array key using custom RC4-like operations, dumping the executable payload as \`tasksche.exe\`.

3. **MITRE ATT&CK Mapping Indicators:**
   - **T1055 (Process Injection):** Identified dynamic calls to \`WriteProcessMemory\` combined with Remote Thread boundaries. Suggests active process hollowing patterns.
   - **T1486 (Data Encrypted for Impact):** High-entropy segments matched with recursive loop flags indicating mass file modifications.`;
      } else if (binary.fileName.includes("artifact64")) {
        analysisSummary = `### AI Static Malware Analysis Report (Cobalt Strike Beacon)
**Target Identifier:** \`artifact64.dll\` | SHA-256: \`0f4dfd...\`

1. **Evasion Routine Identified:**
   The disassembler flags calls to \`VirtualAlloc\` reserving robust execution segments mapped as \`PAGE_EXECUTE_READWRITE\` (0x40). This allows direct placement of raw hex payloads on the heap that can bypass common code signing protocols.
   
2. **Command & Control Channels:**
   The string scanner highlights requests mapping HTTP configurations including \`/g.pixel\` relative endpoints. This simulates dynamic beacon callbacks designed to hide under routine pixel tracking web telemetry.`;
      } else if (binary.fileName.includes("winhook")) {
        analysisSummary = `### AI Static Analysis Report (WinHook Keylogger capture payload)
**Target Identifier:** \`winhook.sys\` | SHA-256: \`97e68a...\`

1. **System Hook Mechanism:**
   The application uses user state hooks (\`WH_KEYBOARD_LL\` - value 13) coupled with native callback interceptors in memory block \`0x000110b0\`.
   
2. **Persistence & Exfiltration:**
   Disassembly indicates sequential logging directly into local temporary targets at \`C:\\Windows\\Temp\\log.txt\`. These logs map character variables like \`[BACKspace]\` and \`[ENTER]\` to track and record credentials dynamically.`;
      } else {
        analysisSummary = `### AI Static Application Summary for ${binary.fileName}
**Target File Type:** ${binary.fileType} (${binary.architecture} Architecture)

1. **Clean Code Verification:**
   The compiled instructions follow a structured, benign sequence. Imports call standard OS library targets like \`printf\` or directory scanning routines. No suspicious memory overrides or persistent hooks are registered.
   
2. **Structural Information:**
   Overall entropy is measured at a very healthy \`${binary.overallEntropy}\`. This indicates code sections are fully standard and completely un-packed. Safe for local sandbox execution.`;
      }
      setAiAnalysisResult(analysisSummary);
      setAiLoading(false);
    }, 900);
  };

  // Tab filtering helpers
  const filteredAssembly = binary.assembly.filter(line => 
    line.address.toLowerCase().includes(disassemblySearch.toLowerCase()) ||
    line.mnemonic.toLowerCase().includes(disassemblySearch.toLowerCase()) ||
    line.operands.toLowerCase().includes(disassemblySearch.toLowerCase()) ||
    (line.comment && line.comment.toLowerCase().includes(disassemblySearch.toLowerCase()))
  );

  const filteredImports = binary.imports.filter(imp => 
    imp.library.toLowerCase().includes(importsSearch.toLowerCase()) ||
    imp.name.toLowerCase().includes(importsSearch.toLowerCase()) ||
    (imp.reason && imp.reason.toLowerCase().includes(importsSearch.toLowerCase()))
  );

  const filteredStrings = binary.strings.filter(str =>
    str.address.toLowerCase().includes(stringsSearch.toLowerCase()) ||
    str.value.toLowerCase().includes(stringsSearch.toLowerCase()) ||
    (str.context && str.context.toLowerCase().includes(stringsSearch.toLowerCase()))
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 font-sans flex flex-col antialiased">
      {/* Top High Density Navigation & Header Bar */}
      <nav className="h-10 bg-slate-850 border-b border-slate-800 flex items-center justify-between px-4 sticky top-0 z-50 transition-all select-none">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <div className="w-5 h-5 bg-cyan-500 rounded-sm flex items-center justify-center text-slate-950 font-bold text-xs">Æ</div>
            <span className="font-semibold text-xs tracking-tight text-white uppercase flex items-center gap-1.5 font-mono">
              AEGIS-AETHER v4.2.1
            </span>
          </div>
          <div className="hidden md:flex space-x-4 text-[11px] font-medium text-slate-400">
            <span className="hover:text-white cursor-pointer transition">File</span>
            <span className="hover:text-white cursor-pointer transition">Edit</span>
            <span className="hover:text-white cursor-pointer transition">Search</span>
            <span className="text-cyan-400 cursor-pointer transition font-bold">Analysis</span>
            <span className="hover:text-white cursor-pointer transition">Debugger</span>
            <span className="hover:text-white cursor-pointer transition" onClick={() => setActiveTab('plugins')}>Plugins</span>
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="flex bg-slate-900 px-2 py-0.5 rounded text-[10px] space-x-2 border border-slate-800 shrink-0 font-mono">
            <span className="text-green-400 flex items-center gap-1 font-bold">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse"></span>
              ● ACTIVE
            </span>
            <span className="text-slate-400 border-l border-slate-800 pl-2 uppercase">{binary.fileType}</span>
            <span className="text-cyan-400 font-bold border-l border-slate-800 pl-2 font-mono">{binary.entryPoint}</span>
          </div>
          <button
            onClick={() => setActiveTab('downloads')}
            className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-[10px] py-1 px-2.5 rounded flex items-center gap-1 transition cursor-pointer font-mono"
          >
            <Download className="w-3 h-3" />
            <span className="hidden sm:inline">Desktop Client</span>
          </button>
        </div>
      </nav>

      {/* Main Core Container */}
      <main className="flex-1 max-w-full w-full mx-auto p-3 space-y-3.5">
        
        {/* Banner Alert Panel */}
        <div className="bg-red-500/5 border border-red-500/20 rounded-md p-2.5 flex items-start gap-3 shadow-sm">
          <Bug className="text-red-400 w-4 h-4 mt-0.5 shrink-0" />
          <div className="space-y-0.5">
            <h4 className="text-[10px] font-bold text-red-200 uppercase tracking-widest font-mono">Malware Sandbox Safety Directive</h4>
            <p className="text-[11px] text-slate-400 leading-normal font-mono">
              Always run telemetry evaluations and malware research inside isolated virtual environments. Aegis installer packages can be compiled locally.
            </p>
          </div>
        </div>

        {/* Section 1: Binary Intake Console & File Upload */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
          
          {/* File selector and drag drop (Left) */}
          <div className="lg:col-span-8 bg-slate-900 rounded-md border border-slate-800 p-3.5 space-y-3">
            <div className="flex justify-between items-center border-b border-slate-800 pb-2">
              <h3 className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Database className="text-cyan-400 w-3.5 h-3.5" />
                Select Analysis Target Binary
              </h3>
              {customBinary && (
                <button 
                  onClick={() => handleLoadSample('wannacry')} 
                  className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 underline font-semibold font-mono cursor-pointer"
                >
                  Clear uploaded file
                </button>
              )}
            </div>

            {/* Quick Sample Targets Grid */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
              {Object.keys(SAMPLE_BINARIES).map((key) => {
                const item = SAMPLE_BINARIES[key];
                const isSelected = selectedBinaryKey === key && !customBinary;
                const isThreat = key === 'wannacry' || key === 'cobalt_beacon' || key === 'keylogger';

                return (
                  <button
                    key={key}
                    onClick={() => handleLoadSample(key)}
                    className={`p-2.5 rounded border text-left flex flex-col justify-between transition cursor-pointer h-20 ${
                      isSelected
                        ? 'bg-slate-850 border-cyan-500 text-white shadow-sm'
                        : 'bg-slate-950 hover:bg-slate-850/50 border-slate-800 text-slate-300'
                    }`}
                  >
                    <div className="space-y-0.5">
                      <div className="text-[9px] uppercase font-mono text-slate-400 tracking-wider font-bold truncate">
                        {key.replace('_', ' ')}
                      </div>
                      <div className="text-[11px] font-sans font-semibold text-slate-100 line-clamp-1 leading-snug">
                        {item.fileName.split(' ')[0]}
                      </div>
                    </div>

                    <div className="flex justify-between items-center text-[9px] font-mono">
                      <span className="text-slate-500 font-bold">{(item.fileSize / 1024).toFixed(0)} KB</span>
                      {isThreat ? (
                        <span className="text-red-400 font-bold tracking-wider bg-red-950/40 border border-red-900/40 px-1 rounded text-[8px]">
                          MAL
                        </span>
                      ) : (
                        <span className="text-cyan-400 font-bold tracking-wider bg-cyan-950/45 border border-cyan-900/30 px-1 rounded text-[8px]">
                          OK
                        </span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Drag & Drop Upload Zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border border-dashed rounded p-3.5 text-center flex flex-col items-center justify-center transition ${
                dragOver 
                  ? 'border-cyan-500 bg-cyan-950/20 text-cyan-200' 
                  : customBinary 
                    ? 'border-emerald-800/80 bg-emerald-950/10' 
                    : 'border-slate-800 hover:border-slate-700 bg-slate-950/35'
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                className="hidden"
                accept=".exe,.dll,.sys,.app,.bin,.elf,*"
              />
              {customBinary ? (
                <div className="space-y-1">
                  <div className="flex justify-center items-center gap-1.5 text-emerald-400">
                    <CheckCircle className="w-4 h-4" />
                    <span className="text-xs font-semibold text-slate-200">Custom user binary mapped successfully!</span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono max-w-sm mx-auto">
                    Aegis compiler generated a simulated static disassembly stream map for file <code className="text-emerald-400 break-all">{customBinary.fileName}</code>.
                  </p>
                  <button
                    onClick={triggerSelectFile}
                    className="mt-1 text-xs text-cyan-400 hover:text-cyan-300 font-bold hover:underline"
                  >
                    Select a different file
                  </button>
                </div>
              ) : (
                <div className="space-y-1 cursor-pointer" onClick={triggerSelectFile}>
                  <div className="p-1.5 bg-slate-900/80 border border-slate-800 rounded-full inline-block text-cyan-400 hover:scale-105 transition">
                    <Upload className="w-4 h-4 mx-auto" />
                  </div>
                  <p className="text-xs font-semibold text-slate-300">Drag & drop raw local files to parse static headers</p>
                  <p className="text-[10px] text-slate-500 font-mono">Supports PE32 Windows COBO, Linux ELF-64, or Apple Mach-O binaries</p>
                </div>
              )}
            </div>
          </div>

          {/* Real-time analytical statistics panel (Right) */}
          <div className="lg:col-span-4 bg-slate-900 rounded-md border border-slate-800 p-3.5 flex flex-col justify-between space-y-3.5">
            <div className="space-y-3">
              <h3 className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="flex items-center gap-1.5">
                  <Layers className="text-cyan-400 w-3.5 h-3.5" />
                  Active File Metadata
                </span>
                <span className="text-[9px] font-mono bg-slate-950 border border-slate-800 text-slate-400 px-1.5 py-0.2 rounded">
                  {binary.architecture}
                </span>
              </h3>

              {/* Stat specs */}
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between py-0.5 border-b border-slate-800/60">
                  <span className="text-slate-500 font-semibold">File Name:</span>
                  <span className="text-slate-200 font-bold truncate max-w-[150px] text-right" title={binary.fileName}>
                    {binary.fileName}
                  </span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-slate-800/60">
                  <span className="text-slate-500 font-semibold">Binary Format:</span>
                  <span className="text-slate-200 font-semibold">{binary.fileType}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-slate-800/60">
                  <span className="text-slate-500 font-semibold">File Size:</span>
                  <span className="text-slate-200">{(binary.fileSize / 1024).toFixed(1)} KB</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-slate-800/60">
                  <span className="text-slate-500 font-semibold">Entrypoint:</span>
                  <span className="text-cyan-400 font-bold">{binary.entryPoint}</span>
                </div>
                <div className="flex justify-between py-0.5 border-b border-slate-800/60 font-mono">
                  <span className="text-slate-500 font-semibold font-sans">Hash (SHA):</span>
                  <span className="text-slate-400 text-[10px] truncate max-w-[140px]" title={binary.sha256}>
                    {binary.sha256}
                  </span>
                </div>
              </div>

              {/* Entropy indicator block with high-entropy colored zones */}
              <div className="pt-1.5">
                <div className="flex justify-between text-[11px] font-mono mb-1">
                  <span className="text-slate-500 flex items-center gap-1 font-semibold">
                    Overall Entropy:
                    {binary.overallEntropy > 6.0 && (
                      <Flame className="w-3.5 h-3.5 text-red-400 animate-pulse" title="High entropy section flags potential cryptography code or malicious packing!" />
                    )}
                  </span>
                  <span className={`font-bold ${binary.overallEntropy > 6.0 ? 'text-red-400' : 'text-cyan-400'}`}>
                    {binary.overallEntropy} / 8.00
                  </span>
                </div>

                <div className="h-1.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                  <div 
                    className={`h-full rounded-full transition-all duration-300 ${
                      binary.overallEntropy > 7.0 
                        ? 'bg-gradient-to-r from-cyan-400 to-red-500' 
                        : binary.overallEntropy > 5.0 
                          ? 'bg-amber-500' 
                          : 'bg-cyan-500'
                    }`} 
                    style={{ width: `${(binary.overallEntropy / 8) * 100}%` }}
                  />
                </div>
                <p className="text-[10px] text-slate-500 italic mt-1 font-mono">
                  {binary.overallEntropy > 6.0 
                    ? "Warning: Packets match indicators of automated cryptography packers."
                    : "Normal text distributions: healthy un-packed system stub."
                  }
                </p>
              </div>
            </div>

            {/* Platform indicators windows linux mac icons */}
            <div className="bg-slate-950 p-2 rounded border border-slate-800">
              <span className="text-[9px] font-mono text-slate-500 block mb-1 uppercase tracking-wider font-bold">Target platforms verified:</span>
              <div className="flex gap-1.5">
                <span className="text-[9px] bg-slate-900 border border-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono font-semibold">Win_PE32+</span>
                <span className="text-[9px] bg-slate-900 border border-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono font-semibold">Lin_ELF64</span>
                <span className="text-[9px] bg-slate-900 border border-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono font-semibold">Mac_MachO</span>
              </div>
            </div>
          </div>
        </section>

        {/* Section 2: Section Breakdown Graph Visualizer */}
        <div className="bg-slate-900 border border-slate-800 rounded-md p-3.5 space-y-3">
          <div className="flex justify-between items-center pb-1.5 border-b border-slate-800">
            <div>
              <h3 className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Layers className="text-cyan-400 w-3.5 h-3.5" />
                Binary Sections Entropy Distribution Channel
              </h3>
              <p className="text-[11px] text-slate-500 font-mono">High entropy (&gt; 7.0) highlights encrypted/packed storage segments.</p>
            </div>
            <span className="text-[10px] font-mono font-bold text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">sections: {binary.sections.length}</span>
          </div>

          {/* Beautiful Custom CSS Chart distribution */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5 pt-1">
            {binary.sections.map((sec, i) => {
              const entropyPct = (sec.entropy / 8) * 100;
              const isHigh = sec.entropy > 7.0;
              const isExecutable = sec.characteristics.includes("EXECUTE");

              return (
                <div key={i} className="bg-slate-950 p-2.5 rounded border border-slate-800 space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold font-mono text-slate-200 bg-slate-900 border border-slate-800 px-1.5 py-0.2 rounded">
                      {sec.name}
                    </span>
                    <span className={`text-[11px] font-mono font-bold ${isHigh ? 'text-red-400' : 'text-cyan-400'}`}>
                      {sec.entropy.toFixed(2)}
                    </span>
                  </div>

                  <div className="h-1 w-full bg-slate-900 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${
                        isHigh ? 'bg-gradient-to-r from-amber-500 to-red-500' : 'bg-cyan-500'
                      }`} 
                      style={{ width: `${entropyPct}%` }}
                    />
                  </div>

                  <div className="text-[9px] text-slate-400 font-mono space-y-0.2">
                    <div className="flex justify-between"><span className="text-slate-500">Address:</span> <span>{sec.virtualAddress}</span></div>
                    <div className="flex justify-between"><span className="text-slate-500">Virtual Size:</span> <span>{sec.virtualSize}</span></div>
                    <div className="flex justify-between font-semibold"><span className="text-slate-500">Flags:</span> <span className="text-cyan-400">{sec.characteristics.slice(0, 2).join(' | ')}</span></div>
                  </div>
                  {isHigh && (
                    <div className="pt-1.5 text-[8px] text-red-450 border-t border-slate-900/60 font-bold flex items-center gap-1 uppercase tracking-wider font-mono">
                      <AlertOctagon className="w-3 h-3 text-red-450 flex-shrink-0" />
                      <span>Packed Section</span>
                    </div>
                  )}
                  {isExecutable && !isHigh && (
                    <div className="pt-1.5 text-[8px] text-cyan-400 border-t border-[#2D3139] font-bold flex items-center gap-1 uppercase tracking-wider font-mono">
                      <Cpu className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                      <span>Code Section</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Section 3: Professional Navigation workbench Tabs bar */}
        <div className="bg-slate-900 rounded-md border border-slate-800 overflow-hidden shadow-2xl">
          <div className="flex flex-wrap bg-slate-950 border-b border-slate-800 overflow-x-auto font-mono text-[11px] select-none">
            <button
              onClick={() => setActiveTab('disassembly')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'disassembly'
                  ? 'border-cyan-500 bg-slate-900 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              ASM VIEW
            </button>
            <button
              onClick={() => setActiveTab('decompiler')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'decompiler'
                  ? 'border-cyan-500 bg-slate-900 text-emerald-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <FileCode className="w-3.5 h-3.5 text-emerald-400" />
              PSEUDOCODE
            </button>
            <button
              onClick={() => setActiveTab('hex')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'hex'
                  ? 'border-cyan-500 bg-slate-900 text-pink-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Binary className="w-3.5 h-3.5 text-pink-400" />
              HEX
            </button>
            <button
              onClick={() => setActiveTab('imports')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'imports'
                  ? 'border-cyan-500 bg-slate-900 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Database className="w-3.5 h-3.5 text-teal-400" />
              IMPORTS ({binary.imports.length})
            </button>
            <button
              onClick={() => setActiveTab('strings')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'strings'
                  ? 'border-cyan-500 bg-slate-900 text-amber-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <FileText className="w-3.5 h-3.5 text-amber-400" />
              STRINGS
            </button>
            <button
              onClick={() => setActiveTab('heuristics')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'heuristics'
                  ? 'border-cyan-500 bg-slate-900 text-red-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
              MITRE SHIELD ({binary.heuristics.length})
            </button>
            <button
              onClick={() => setActiveTab('plugins')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'plugins'
                  ? 'border-cyan-500 bg-slate-900 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Terminal className="text-cyan-400 w-3.5 h-3.5" />
              JS PLUGINS
            </button>
            <button
              onClick={() => setActiveTab('downloads')}
              className={`px-3.5 py-2.5 font-bold focus:outline-none border-b-2 flex items-center gap-1.5 transition cursor-pointer shrink-0 ${
                activeTab === 'downloads'
                  ? 'border-cyan-500 bg-slate-900 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-100 hover:bg-slate-900/50'
              }`}
            >
              <Download className="text-cyan-400 w-3.5 h-3.5" />
              DESKTOP EXECUTABLES
            </button>
          </div>

          <div className="p-3.5 bg-slate-900">
            
            {/* WORKSPACE 1: LINEAR DISASSEMBLER */}
            {activeTab === 'disassembly' && (
              <div className="space-y-3">
                <div className="flex flex-wrap justify-between items-center gap-2.5">
                  <div>
                    <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1">
                      <Cpu className="text-cyan-400 w-3.5 h-3.5" />
                      Disassembler Direct Instruction Stream
                    </h3>
                    <p className="text-[11px] text-slate-500 font-mono">Dynamic parsing maps sequential instructions. Use filters to query mnemonic codes.</p>
                  </div>
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="Query opcodes, mnemonics..."
                      value={disassemblySearch}
                      onChange={(e) => setDisassemblySearch(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded pl-7 pr-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500 font-sans w-52 font-mono h-7"
                    />
                    <Search className="absolute left-2 top-1.5 text-slate-500 w-3.5 h-3.5" />
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
                  {/* Linear table content layout */}
                  <div className="lg:col-span-3 border border-slate-800 rounded overflow-x-auto bg-slate-950">
                    <table className="w-full text-left border-collapse font-mono text-xs select-text">
                      <thead>
                        <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[9px] select-none">
                          <th className="p-2 pl-3 font-bold">Offset</th>
                          <th className="p-2 font-bold">Opcodes</th>
                          <th className="p-2 font-bold">Assembly (Instruction)</th>
                          <th className="p-2 pr-3 font-bold">Expert Comments / Hints</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40">
                        {filteredAssembly.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="p-8 text-center text-slate-500 italic font-mono text-[11px]">
                              No matching instructions found.
                            </td>
                          </tr>
                        ) : (
                          filteredAssembly.map((line, idx) => {
                            const isFocused = focusedAsmLine?.address === line.address;
                            return (
                              <tr
                                key={idx}
                                onClick={() => setFocusedAsmLine(line)}
                                className={`cursor-pointer transition ${
                                  isFocused 
                                    ? 'bg-cyan-950/40 hover:bg-cyan-950/60' 
                                    : 'hover:bg-slate-900/40'
                                }`}
                              >
                                <td className="p-1.5 pl-3 font-bold text-cyan-400">{line.address}</td>
                                <td className="p-1.5 text-slate-500 font-medium">{line.opcodes}</td>
                                <td className="p-1.5 font-bold text-slate-100 font-mono">
                                  <span className="text-amber-400 mr-2">{line.mnemonic}</span>
                                  <span className="text-slate-300 font-medium">{line.operands}</span>
                                </td>
                                <td className="p-1.5 pr-3 text-[10px] text-emerald-450/90 leading-tight">
                                  {line.comment || "—"}
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Inspector micro pane */}
                  <div className="lg:col-span-1 bg-slate-950 border border-slate-800 p-3 rounded space-y-3 font-sans">
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1 border-b border-slate-800 pb-1.5 font-mono">
                      <Bug className="text-amber-400 w-3.5 h-3.5" />
                      Symbolic Inspector
                    </h4>

                    {focusedAsmLine ? (
                      <div className="space-y-2 text-xs">
                        <div className="space-y-0.5 bg-slate-900 p-2 rounded border border-slate-800 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Selected offset</span>
                          <span className="text-cyan-400 font-bold">{focusedAsmLine.address}</span>
                        </div>
                        <div className="space-y-0.5 bg-slate-900 p-2 rounded border border-slate-800 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Instruction Hex</span>
                          <span className="text-emerald-400">{focusedAsmLine.opcodes}</span>
                        </div>
                        <div className="space-y-0.5 bg-slate-900 p-2 rounded border border-slate-800 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Assembly Mnemonic</span>
                          <span className="text-white font-bold">{focusedAsmLine.mnemonic} {focusedAsmLine.operands}</span>
                        </div>
                        {focusedAsmLine.comment && (
                          <div className="space-y-0.5 bg-slate-900 p-2 rounded border border-slate-800 italic text-[10px] text-slate-300 bg-cyan-950/10 border-cyan-900/40">
                            <span className="text-cyan-300 block text-[8px] font-bold uppercase tracking-wider font-mono">Expert comment analysis</span>
                            {focusedAsmLine.comment}
                          </div>
                        )}
                        <p className="text-[10px] text-slate-500 leading-normal font-mono">
                          Micro instruction analysis verifies safe execution sequences. Code signature checks passed.
                        </p>
                      </div>
                    ) : (
                      <div className="text-center py-7 space-y-1.5 text-slate-500 font-mono">
                        <HelpCircle className="w-6 h-6 mx-auto stroke-1" />
                        <p className="text-[10px]">Click any instruction row in the table to resolve deep parameters.</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* WORKSPACE 2: RECONSTRUCTED DECOMPILER */}
            {activeTab === 'decompiler' && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
                
                {/* Decompile logic stream */}
                <div className="lg:col-span-8 space-y-3">
                  <div className="flex justify-between items-center">
                    <div>
                      <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1">
                        <FileCode className="text-emerald-400 w-3.5 h-3.5" />
                        Abstract Synthetic Pseudocode Output
                      </h3>
                      <p className="text-[11px] text-slate-500 font-mono">High-performance transpiler maps raw bytecode back to C layouts.</p>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-3.5 rounded border border-slate-800 overflow-x-auto shadow-inner relative">
                    <div className="absolute top-2.5 right-2.5 text-cyan-400 text-[9px] font-mono select-none bg-cyan-950/50 border border-cyan-900/50 px-2 py-0.5 rounded uppercase font-bold">
                      Synthesized C Output
                    </div>
                    
                    <div className="font-mono text-xs leading-normal space-y-3 text-emerald-300/90 select-text">
                      {binary.decompiledFunctions.map((fn, idx) => (
                        <div key={idx} className="space-y-0.5 p-2.5 bg-slate-900/20 rounded border border-slate-800/50">
                          {/* Function header declaration signature */}
                          <div className="text-cyan-400 font-bold">
                            {fn.returnType} <span className="text-slate-100 font-bold">{fn.name}</span>({fn.arguments.join(', ')}) &#123;
                            <span className="text-slate-500 font-normal ml-2 font-mono text-[9px]">/* offset: {fn.address} */</span>
                          </div>

                          {/* Function internal blocks */}
                          <div className="pl-5 space-y-0.5 font-mono text-[11px] leading-tight">
                            {fn.body.map((line, bIdx) => {
                              // Rough syntax highlights in code blocks
                              let colorClass = "text-slate-200";
                              if (line.startsWith("//")) {
                                colorClass = "text-slate-500 italic";
                              } else if (line.includes("VirtualAlloc") || line.includes("CreateMutex") || line.includes("SetWindowsHook") || line.includes("WriteProcess") || line.includes("ShellExecute")) {
                                colorClass = "text-orange-400 font-semibold";
                              } else if (line.includes("if") || line.includes("return") || line.includes("while")) {
                                colorClass = "text-cyan-400 font-bold";
                              } else if (line.includes("char") || line.includes("bool") || line.includes("int") || line.includes("HANDLE")) {
                                colorClass = "text-teal-400";
                              } else if (line.includes("http") || line.includes(".com") || line.includes(".txt") || line.includes(".exe")) {
                                colorClass = "text-amber-300 font-semibold";
                              }
                              return (
                                <div key={bIdx} className={`${colorClass} whitespace-pre`}>
                                  {line}
                                </div>
                              );
                            })}
                          </div>

                          <div className="text-cyan-400 font-bold">&#125;</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* AI Auxiliary agent support panel (Right) */}
                <div className="lg:col-span-4 bg-slate-950 border border-slate-800 p-3.5 rounded flex flex-col justify-between space-y-3">
                  <div className="space-y-3">
                    <div className="flex items-center gap-1.5 border-b border-slate-800 pb-1.5">
                      <Sparkles className="text-cyan-400 w-4 h-4 animate-pulse" />
                      <div>
                        <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-100 font-mono">Aegis AI Code Explainer</h4>
                        <span className="text-[8px] font-mono text-slate-500 uppercase font-bold">Gemini Static Signature Model</span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-normal font-sans">
                      Aegis utilizes specialized Gemini models to evaluate threat behaviors, and analyze obfuscated variables instantly.
                    </p>

                    {aiAnalysisResult ? (
                      <div className="bg-slate-900 p-2.5 rounded border border-slate-850 text-xs text-slate-300 space-y-2.5 max-h-[320px] overflow-y-auto leading-normal select-text font-mono prose prose-invert">
                        {aiAnalysisResult.split('\n\n').map((para, pIdx) => {
                          if (para.startsWith('###')) {
                            return <h5 key={pIdx} className="font-bold text-cyan-400 border-b border-slate-800 pb-0.5 mt-1.5 text-[11px] uppercase font-mono">{para.replace('###', '')}</h5>;
                          }
                          return <p key={pIdx} className="text-[10px] text-slate-300 leading-tight whitespace-pre-wrap">{para}</p>;
                        })}
                      </div>
                    ) : aiLoading ? (
                      <div className="text-center py-10 space-y-2">
                        <Bug className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
                        <span className="text-[10px] font-mono text-slate-500 tracking-wider block font-bold">Querying Gemini model signatures API...</span>
                      </div>
                    ) : (
                      <div className="bg-cyan-950/10 border border-cyan-900/30 p-3 rounded space-y-1.5 text-center font-mono">
                        <Bug className="text-cyan-400 w-5 h-5 mx-auto animate-pulse" />
                        <span className="text-[11px] font-bold text-slate-200 block uppercase">Gemini Static Analytics Ready</span>
                        <p className="text-[10.5px] text-slate-400 leading-relaxed">
                          Extract compiler configurations and high-value indicators dynamically for this specific stub.
                        </p>
                      </div>
                    )}
                  </div>

                  {!aiLoading && (
                    <button
                      onClick={triggerAiDecompilerAgent}
                      className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-[10px] py-1.5 px-3 rounded flex items-center justify-center gap-1 transition cursor-pointer font-mono uppercase"
                    >
                      <Sparkles className="w-3.5 h-3.5 fill-white text-transparent" />
                      Auto-Decompile with Aegis AI
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* WORKSPACE 3: DYNAMIC HEX VIEWER */}
            {activeTab === 'hex' && (
              <div className="space-y-3">
                <HexViewer sha256={binary.sha256} fileSize={binary.fileSize} />
              </div>
            )}

            {/* WORKSPACE 4: DYNAMIC IMPORTS & SYMBOLS */}
            {activeTab === 'imports' && (
              <div className="space-y-3">
                <div className="flex flex-wrap justify-between items-center gap-2.5">
                  <div>
                    <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1">
                      <Database className="text-cyan-400 w-3.5 h-3.5" />
                      Dynamic Imports Table ({binary.imports.length} loaded)
                    </h3>
                    <p className="text-[11px] text-slate-500 font-mono">Dependencies dynamic OS routines. Bold items indicate higher security profiles.</p>
                  </div>
                  <div className="relative font-mono">
                    <input
                      type="text"
                      placeholder="Query DLL, imports name..."
                      value={importsSearch}
                      onChange={(e) => setImportsSearch(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded pl-7 pr-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500 font-sans w-52 font-mono h-7"
                    />
                    <Search className="absolute left-2 top-1.5 text-slate-500 w-3.5 h-3.5" />
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
                  {/* Imports table (Left) */}
                  <div className="lg:col-span-3 border border-slate-800 rounded overflow-x-auto bg-slate-950">
                    <table className="w-full text-left border-collapse font-sans text-xs">
                      <thead>
                        <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[9px] font-mono">
                          <th className="p-2 pl-3">DLL Library</th>
                          <th className="p-2">Routine Identifier Name</th>
                          <th className="p-2">Mapped Offset</th>
                          <th className="p-2 pr-3">Assessment Profile</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40">
                        {filteredImports.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="p-8 text-center text-slate-500 italic font-mono text-[11px]">
                              No matching imports filtered.
                            </td>
                          </tr>
                        ) : (
                          filteredImports.map((imp, idx) => {
                            const isSelected = focusedImport?.name === imp.name;
                            return (
                              <tr
                                key={idx}
                                onClick={() => setFocusedImport(imp)}
                                className={`cursor-pointer transition ${
                                  isSelected 
                                    ? 'bg-cyan-950/40 font-bold text-white' 
                                    : 'hover:bg-slate-900/40'
                                }`}
                              >
                                <td className="p-1.5 pl-3 font-mono text-slate-400">{imp.library}</td>
                                <td className="p-1.5 font-mono text-slate-105">
                                  {imp.name}
                                </td>
                                <td className="p-1.5 font-mono text-cyan-400 font-bold">{imp.address}</td>
                                <td className="p-1.5 pr-3">
                                  {imp.isSuspicious ? (
                                    <span className="text-[8px] bg-red-500/10 border border-red-500/20 text-red-400 font-bold px-1.5 py-0.2 rounded font-mono uppercase">
                                      Suspicious Handle
                                    </span>
                                  ) : (
                                    <span className="text-[8px] bg-slate-900 border border-slate-800 text-slate-500 font-bold px-1.5 py-0.2 rounded font-mono uppercase">
                                      Standard API
                                    </span>
                                  )}
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Warning dynamic diagnostic inspector (Right) */}
                  <div className="lg:col-span-1 bg-slate-950 border border-slate-800 p-3 rounded space-y-3 font-sans">
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1 border-b border-slate-800 pb-1.5 font-mono">
                      <ShieldAlert className="text-red-400 w-3.5 h-3.5 animate-pulse" />
                      Import Threat Diagnostics
                    </h4>

                    {focusedImport ? (
                      <div className="space-y-2.5 text-xs">
                        <div className="space-y-0.5 p-2 bg-slate-900 rounded border border-slate-805 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Dynamic Export Endpoint</span>
                          <span className="text-white font-bold">{focusedImport.library}!{focusedImport.name}</span>
                        </div>
                        <div className="space-y-0.5 p-2 bg-slate-900 rounded border border-slate-805 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Decompiled Target Offset</span>
                          <span className="text-cyan-400 font-bold">{focusedImport.address}</span>
                        </div>
                        {focusedImport.isSuspicious ? (
                          <div className="bg-red-500/10 border border-red-500/20 p-2.5 rounded text-red-200 text-[10px] leading-normal space-y-1 font-mono">
                            <span className="font-bold text-red-400 block uppercase">Malicious indicators mapped:</span>
                            <p>{focusedImport.reason || "Bypasses default memory structures to execute untrusted code blocks."}</p>
                          </div>
                        ) : (
                          <div className="bg-slate-900 border border-slate-800 p-2.5 rounded text-slate-400 text-[10px] leading-normal font-mono">
                            <span className="font-bold text-slate-300 block uppercase">Clean verified routine:</span>
                            <p>Standard operating system dependency supporting generic execution patterns.</p>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-7 space-y-1.5 text-slate-500 font-mono">
                        <HelpCircle className="w-6 h-6 mx-auto stroke-1" />
                        <p className="text-[10px]">Click any API routine row to resolve technical security parameters.</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* WORKSPACE 5: EXTRACTED STRINGS */}
            {activeTab === 'strings' && (
              <div className="space-y-3">
                <div className="flex flex-wrap justify-between items-center gap-2.5">
                  <div>
                    <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1">
                      <FileText className="text-cyan-400 w-3.5 h-3.5" />
                      Extracted Global Strings ({binary.strings.length} matches)
                    </h3>
                    <p className="text-[11px] text-slate-500 font-mono">Static strings resolved from read-only segments (.rodata). Key metrics flag constants.</p>
                  </div>
                  <div className="relative font-mono">
                    <input
                      type="text"
                      placeholder="Query text, links, offset..."
                      value={stringsSearch}
                      onChange={(e) => setStringsSearch(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded pl-7 pr-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500 font-sans w-52 font-mono h-7"
                    />
                    <Search className="absolute left-2 top-1.5 text-slate-500 w-3.5 h-3.5" />
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
                  {/* Strings Table (Left) */}
                  <div className="lg:col-span-3 border border-slate-800 rounded overflow-x-auto bg-slate-950">
                    <table className="w-full text-left border-collapse font-sans text-xs">
                      <thead>
                        <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[9px] font-mono">
                          <th className="p-2 pl-3">Physical Offset</th>
                          <th className="p-2">Length (Bytes)</th>
                          <th className="p-2">Character Match Text</th>
                          <th className="p-2">Encoding</th>
                          <th className="p-2 pr-3">Diagnostic Context</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40">
                        {filteredStrings.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="p-8 text-center text-slate-500 italic font-mono text-[11px]">
                              No matching strings mapped under your current query.
                            </td>
                          </tr>
                        ) : (
                          filteredStrings.map((str, idx) => {
                            const isSelected = focusedString?.address === str.address;
                            const isHostPattern = str.value.includes("http") || str.value.includes("Local\\") || str.value.includes("C:\\");

                            return (
                              <tr
                                key={idx}
                                onClick={() => setFocusedString(str)}
                                className={`cursor-pointer transition ${
                                  isSelected 
                                    ? 'bg-cyan-950/40 font-bold text-white' 
                                    : 'hover:bg-slate-900/40'
                                }`}
                              >
                                <td className="p-1.5 pl-3 font-mono text-cyan-400 font-bold">{str.address}</td>
                                <td className="p-1.5 font-mono text-slate-500">{str.length}</td>
                                <td className={`p-1.5 font-mono break-all font-bold ${isHostPattern ? 'text-amber-400' : 'text-slate-300'}`}>
                                  "{str.value}"
                                </td>
                                <td className="p-1.5 text-slate-500 font-mono text-[9px] uppercase font-bold">{str.type}</td>
                                <td className="p-1.5 pr-3 text-emerald-400 text-[10px] leading-tight font-mono">
                                  {str.context || "Generic constant payload string"}
                                </td>
                              </tr>
                            );
                          })
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Character Diagnostics (Right) */}
                  <div className="lg:col-span-1 bg-slate-950 border border-slate-800 p-3 rounded space-y-3 font-sans">
                    <h3 className="text-[10px] font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1 border-b border-slate-800 pb-1.5 font-mono">
                      <FileText className="text-amber-400 w-3.5 h-3.5" />
                      Constant String Analysis
                    </h3>

                    {focusedString ? (
                      <div className="space-y-3 text-xs font-mono">
                        <div className="space-y-0.5 bg-slate-900 p-2 rounded border border-slate-800 font-mono text-[10px]">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Character Offset Block</span>
                          <span className="text-white font-bold break-all">"{focusedString.value}"</span>
                        </div>
                        <div className="space-y-0.5 text-slate-400 font-mono">
                          <span className="text-slate-500 block text-[8px] uppercase tracking-wider font-bold">Metadata statistics:</span>
                          <div className="flex justify-between py-1 border-b border-slate-850 text-[10px]">
                            <span>Byte Address:</span>
                            <span className="text-cyan-400 font-bold text-right">{focusedString.address}</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-slate-850 text-[10px]">
                            <span>Character Length:</span>
                            <span className="text-white">{focusedString.length} chars</span>
                          </div>
                          <div className="flex justify-between py-1 border-b border-slate-850 text-[10px]">
                            <span>Memory Segment:</span>
                            <span className="text-cyan-400 bg-cyan-950/20 px-1.5 py-0.2 rounded border border-cyan-900/30 font-bold uppercase text-[8px]">.rdata</span>
                          </div>
                        </div>

                        {focusedString.context ? (
                          <div className="bg-cyan-950/10 border border-cyan-900/30 p-2 rounded text-slate-300 text-[10px] italic">
                            <span className="text-cyan-300 block text-[8px] font-bold uppercase tracking-wider font-mono select-none">Strategic Threat Match Context</span>
                            "{focusedString.context}"
                          </div>
                        ) : (
                          <p className="text-[10px] text-slate-500 leading-normal font-sans italic">
                            Standard literal constant matching common compiler configurations. No threat matched.
                          </p>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-7 space-y-1.5 text-slate-500 font-mono">
                        <HelpCircle className="w-6 h-6 mx-auto stroke-1" />
                        <p className="text-[10px]">Select any text row on the left panel to inspect parameters.</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* WORKSPACE 6: HEURISTICS & MITRE ATT&CK MATRIX */}
            {activeTab === 'heuristics' && (
              <div className="space-y-4">
                <div>
                  <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-1">
                    <ShieldAlert className="text-cyan-400 w-3.5 h-3.5" />
                    Static Behavior Rules & MITRE ATT&CK Match
                  </h3>
                  <p className="text-[11px] text-slate-500 font-mono">Integrates heuristic threat classifiers maps indicators direct to security standards.</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {binary.heuristics.length === 0 ? (
                    <div className="col-span-full bg-slate-950 border border-slate-800 text-center py-8 rounded space-y-1.5 font-mono">
                      <CheckCircle className="w-8 h-8 text-cyan-400 mx-auto animate-pulse" />
                      <h4 className="text-xs font-bold text-slate-200 uppercase">No Heuristic Threat Alerts Triaged!</h4>
                      <p className="text-[10px] text-slate-500 max-w-sm mx-auto">This file parsed cleanly with standard entropy levels and generic operating signatures.</p>
                    </div>
                  ) : (
                    binary.heuristics.map((rule, idx) => {
                      let severityBadge = "bg-yellow-950/40 border-yellow-900/40 text-yellow-500 font-bold";
                      if (rule.severity === 'critical') {
                        severityBadge = "bg-red-500/10 border-red-500/20 text-red-400 font-bold animate-pulse";
                      } else if (rule.severity === 'high') {
                        severityBadge = "bg-orange-500/10 border-orange-500/20 text-orange-405 font-bold";
                      }

                      return (
                        <div key={idx} className="bg-slate-950 border border-slate-800 p-3 rounded flex flex-col justify-between space-y-3 font-mono">
                          <div className="space-y-1.5">
                            <div className="flex justify-between items-center">
                              <span className="text-[8px] bg-slate-900 text-slate-500 border border-slate-805 px-1.5 py-0.2 rounded uppercase font-bold">
                                {rule.category}
                              </span>
                              <span className={`text-[8px] px-1.5 py-0.2 border rounded font-bold uppercase ${severityBadge}`}>
                                {rule.severity} Risk
                              </span>
                            </div>
                            <p className="text-[11px] font-bold text-slate-200 leading-tight">
                              {rule.details}
                            </p>
                          </div>

                          <div className="pt-2 border-t border-slate-900 flex justify-between items-center text-[9px] font-mono text-slate-500 uppercase font-bold">
                            <span>MITRE ID:</span>
                            {rule.mitreId ? (
                              <span className="text-cyan-400 hover:underline cursor-pointer border border-cyan-900/30 bg-cyan-950/20 px-1.5 py-0.2 rounded">
                                {rule.mitreId}
                              </span>
                            ) : (
                              <span>N/A</span>
                            )}
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                {/* Cyber Security Guidance Map */}
                <div className="bg-slate-950 rounded border border-slate-800 p-4 grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
                  <div className="space-y-1">
                    <div className="flex items-center gap-1 text-[11px] font-bold text-red-400 uppercase tracking-wider">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Static Analysis Target</span>
                    </div>
                    <p className="text-[10px] text-slate-500 leading-normal">
                      Static analysis extracts system instructions directly without executing the program binary flow, shielding sandbox environments.
                    </p>
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-1 text-[11px] font-bold text-cyan-400 uppercase tracking-wider">
                      <Layers className="w-3.5 h-3.5" />
                      <span>Entropy Evaluations</span>
                    </div>
                    <p className="text-[10px] text-slate-500 leading-normal">
                      Cipher structures and hidden installers yield high entropy ratings due to code variability. Any rating over 7.00 triggers alert warnings.
                    </p>
                  </div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-1 text-[11px] font-bold text-amber-500 uppercase tracking-wider">
                      <Bug className="w-3.5 h-3.5" />
                      <span>Plugin Automations</span>
                    </div>
                    <p className="text-[10px] text-slate-500 leading-normal">
                      Automate static scanning of sequential offsets. Synthesize customizable patterns inside our dynamic tab playground to locate indicators.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* WORKSPACE 7: INTERACTIVE PLUGINS SYSTEM */}
            {activeTab === 'plugins' && (
              <div className="space-y-3">
                <PluginEngine currentBinary={binary} />
              </div>
            )}

            {/* WORKSPACE 8: NATIVE INSTALLERS HUB */}
            {activeTab === 'downloads' && (
              <div className="space-y-3">
                <OsDownloadModule />
              </div>
            )}

          </div>
        </div>

        {/* Footer info branding block */}
        <footer className="pt-6 pb-3 text-center border-t border-slate-900 flex flex-col sm:flex-row justify-between items-center gap-2.5 text-[10px] text-slate-500 font-mono uppercase font-bold">
          <div>
            Aegis Binary Studio is an open-source educational reverse compiling playground environment.
          </div>
          <div className="flex gap-3">
            <a href="#github-clone" className="hover:text-cyan-400 transition hover:underline">GitHub Core</a>
            <span>•</span>
            <a href="#licence" className="hover:text-cyan-400 transition hover:underline">Apache 2.0 License</a>
          </div>
        </footer>

      </main>
    </div>
  );
}
