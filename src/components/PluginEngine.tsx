import React, { useState, useEffect } from 'react';
import { BinaryMetadata, PluginScript } from '../types';
import { DEFAULT_PLUGINS, runSandboxPlugin } from '../plugins';
import { Play, RotateCcw, AlertTriangle, Cpu, Terminal, Sparkles, HelpCircle, FileCode } from 'lucide-react';

interface PluginEngineProps {
  currentBinary: BinaryMetadata;
}

export const PluginEngine: React.FC<PluginEngineProps> = ({ currentBinary }) => {
  const [plugins, setPlugins] = useState<PluginScript[]>(DEFAULT_PLUGINS);
  const [selectedPluginId, setSelectedPluginId] = useState<string>(DEFAULT_PLUGINS[0].id);
  const [scriptCode, setScriptCode] = useState<string>(DEFAULT_PLUGINS[0].code);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    "[*System] Antigravity Sandbox Shell initialized.",
    `[*System] Target binary loaded: ${currentBinary.fileName}. Ready to intercept dynamic execution pipelines.`,
    "[Instructions] Pick a plugin framework template below, adjust code as desired, and trigger compile and run."
  ]);

  const activePlugin = plugins.find(p => p.id === selectedPluginId);

  // Sync script editor when user switches between different baseline plugins
  useEffect(() => {
    if (activePlugin) {
      setScriptCode(activePlugin.code);
    }
  }, [selectedPluginId, plugins]);

  const appendTerminalLog = (message: string) => {
    setTerminalLogs(prev => [...prev, message]);
  };

  const handleRunPlugin = () => {
    if (!activePlugin) return;

    // Create updated temporary state instance representing edited code in-editor
    const executableInstance: PluginScript = {
      ...activePlugin,
      code: scriptCode
    };

    runSandboxPlugin(executableInstance, currentBinary, appendTerminalLog);
    
    // Auto scroll the telemetry logs view if possible
    setTimeout(() => {
      const loggerDiv = document.getElementById("terminal-console-output");
      if (loggerDiv) {
        loggerDiv.scrollTop = loggerDiv.scrollHeight;
      }
    }, 100);
  };

  const handleResetPlugin = () => {
    const original = DEFAULT_PLUGINS.find(p => p.id === selectedPluginId);
    if (original) {
      setScriptCode(original.code);
      appendTerminalLog(`[*System] Reset in-editor code payload for: "${original.name}" template.`);
    }
  };

  const clearTerminalLogs = () => {
    setTerminalLogs([`[*System] Console output buffer cleared. Hot module ready for target: ${currentBinary.fileName}`]);
  };

  // Helper template inserters for beginner users
  const insertCodeHelper = (type: 'print' | 'importScan' | 'searchString') => {
    let helper = '';
    if (type === 'print') {
      helper = `\nprint("Current binary structure size: " + binary.fileSize + " bytes");\n`;
    } else if (type === 'importScan') {
      helper = `\n// Loop and flag KERNEL32 dynamic calls
binary.imports.forEach(imp => {
  if(imp.library.toLowerCase().includes("kernel32")) {
    print("[Helper Match] KERNEL32 API: " + imp.name);
  }
});\n`;
    } else if (type === 'searchString') {
      helper = `\n// Look for specific string tags
const containsKey = binary.strings.filter(s => s.value.toLowerCase().includes("key"));
print("Identified matching string tokens count: " + containsKey.length);\n`;
    }
    setScriptCode(prev => prev + helper);
    appendTerminalLog("[Code Helper] Inserted snippet block at the bottom of the script.");
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-md overflow-hidden shadow-2xl">
      {/* Banner */}
      <div className="bg-slate-950 p-3 border-b border-slate-800 flex flex-wrap justify-between items-center gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="text-cyan-400 w-4 h-4 animate-pulse" />
          <div>
            <h2 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">Interactive Plugin Sandbox Console</h2>
            <p className="text-[11px] text-slate-500 font-mono">Automate malware signature searches, instruction matching, and string heuristics live.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono bg-[#0F111A] border border-cyan-900/50 text-cyan-400 px-2 py-0.5 rounded flex items-center gap-1.5 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
            ACTIVE SYNTHESIZER
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-slate-800">
        {/* Left Side: Control panel + Script Editor */}
        <div className="lg:col-span-7 p-3.5 space-y-3.5">
          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 font-bold uppercase tracking-wider font-mono block">Select Plugin Template:</label>
            <div className="flex gap-1.5">
              <select
                value={selectedPluginId}
                onChange={(e) => setSelectedPluginId(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500 font-mono"
              >
                {plugins.map(plugin => (
                  <option key={plugin.id} value={plugin.id}>
                    {plugin.name} (by {plugin.author})
                  </option>
                ))}
              </select>
              <button
                onClick={handleResetPlugin}
                title="Reset code template"
                className="bg-slate-950 border border-slate-800 hover:bg-slate-800 text-slate-300 hover:text-white p-1.5 rounded transition cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
            {activePlugin && (
              <p className="text-[11px] text-slate-400 italic bg-slate-950/40 p-2 rounded border border-slate-800/40 leading-normal font-mono">
                {activePlugin.description}
              </p>
            )}
          </div>

          {/* Script Editor Pane */}
          <div className="space-y-1">
            <div className="flex justify-between items-center text-[10px] font-mono">
              <span className="text-slate-400 font-bold flex items-center gap-1 uppercase tracking-wider">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                Script Source Editor (ES6 JS Subsystem)
              </span>
              <div className="flex gap-1">
                <button
                  onClick={() => insertCodeHelper('print')}
                  className="bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-cyan-400 px-1.5 py-0.2 rounded text-[9px] font-mono transition cursor-pointer"
                >
                  + Print Helper
                </button>
                <button
                  onClick={() => insertCodeHelper('importScan')}
                  className="bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-cyan-400 px-1.5 py-0.2 rounded text-[9px] font-mono transition cursor-pointer"
                >
                  + Scan Imports
                </button>
                <button
                  onClick={() => insertCodeHelper('searchString')}
                  className="bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-cyan-400 px-1.5 py-0.2 rounded text-[9px] font-mono transition cursor-pointer"
                >
                  + Read Strings
                </button>
              </div>
            </div>

            <div className="relative rounded overflow-hidden border border-slate-800 font-mono text-xs shadow-inner">
              {/* Code line numbers count column mockup */}
              <div className="absolute top-0 bottom-0 left-0 w-8 bg-slate-950 border-r border-slate-805 flex flex-col items-center pt-2.5 text-[9px] text-slate-600 select-none">
                {Array.from({ length: 25 }).map((_, i) => (
                  <div key={i} className="leading-tight h-[18px]">{i + 1}</div>
                ))}
              </div>
              
              <textarea
                value={scriptCode}
                onChange={(e) => setScriptCode(e.target.value)}
                rows={12}
                className="w-full bg-slate-950 pl-10 pr-3 pt-2.5 pb-2.5 text-slate-300 outline-none text-[11px] leading-tight font-mono relative z-10 resize-y"
                style={{ lineHeight: '18px' }}
                placeholder="// Write custom analytical scripts here using the 'binary' object parameters..."
              />
            </div>
            <div className="flex justify-between items-center text-[10px] text-slate-500 font-mono">
              <span className="flex items-center gap-1 bg-slate-950/50 py-0.5 px-2 rounded border border-slate-800/40">
                <Sparkles className="w-3 h-3 text-amber-500" />
                Globals exposed: <code className="text-cyan-400">binary</code>, <code className="text-cyan-400">print()</code>
              </span>
              <span className="font-bold">UTF-8 Script Payload</span>
            </div>
          </div>

          <button
            onClick={handleRunPlugin}
            className="w-full bg-cyan-600 hover:bg-cyan-500 text-white py-1.5 px-3 rounded font-bold text-[11px] flex items-center justify-center gap-1.5 cursor-pointer transition shadow-lg shadow-cyan-950 font-mono uppercase"
          >
            <Play className="w-3.5 h-3.5 fill-white text-transparent" />
            Synthesize & Evaluate Script Live
          </button>
        </div>

        {/* Right Side: stdout debugger screen */}
        <div className="lg:col-span-5 p-3.5 flex flex-col bg-slate-950">
          <div className="flex justify-between items-center mb-1.5">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1 font-mono">
              <Cpu className="text-cyan-400 w-3.5 h-3.5" />
              Standard System Output (stdout)
            </span>
            <button
              onClick={clearTerminalLogs}
              className="text-[9px] bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 py-0.5 px-2 rounded transition font-mono uppercase font-bold cursor-pointer"
            >
              Clear Buffer
            </button>
          </div>

          {/* Core terminal screen */}
          <div
            id="terminal-console-output"
            className="flex-1 min-h-[300px] lg:min-h-[320px] bg-black text-[#5ef71d] font-mono text-[11px] p-3 rounded border border-slate-900 overflow-y-auto space-y-1 select-text shadow-inner"
          >
            {terminalLogs.map((log, index) => {
              // Context coloration highlighting level patterns
              let rowColor = "text-[#5ef71d]";
              if (log.startsWith("[ERROR]")) {
                rowColor = "text-red-400 font-bold";
              } else if (log.startsWith("[*System]")) {
                rowColor = "text-cyan-400 font-bold";
              } else if (log.startsWith(">>>")) {
                rowColor = "text-cyan-300 font-bold border-t border-b border-slate-900 my-0.5 py-0.2";
              } else if (log.includes("[WARNING]") || log.includes("[ALERT")) {
                rowColor = "text-amber-400 font-semibold";
              } else if (log.startsWith("[OK]")) {
                rowColor = "text-emerald-300 font-semibold";
              } else if (log.startsWith("[Instructions]")) {
                rowColor = "text-slate-500 italic";
              }

              return (
                <div key={index} className={`whitespace-pre-wrap font-mono leading-tight ${rowColor}`}>
                  {log}
                </div>
              );
            })}
          </div>

          {/* Quick instructions and API lookup */}
          <div className="mt-2.5 p-2 rounded bg-slate-900/60 border border-slate-800/80 font-mono">
            <h4 className="text-[10px] font-bold text-slate-300 flex items-center gap-1 mb-1 uppercase tracking-wider">
              <HelpCircle className="w-3 h-3 text-cyan-400" />
              SDK Reference Guide
            </h4>
            <div className="text-[9px] text-slate-500 space-y-0.5 leading-relaxed font-mono">
              <div>• <code className="text-slate-300 font-bold">binary.fileName</code>: target identity string</div>
              <div>• <code className="text-slate-300 font-bold">binary.fileSize</code>: file size number bytes</div>
              <div>• <code className="text-slate-300 font-bold">binary.entryPoint</code>: binary code entry threshold</div>
              <div>• <code className="text-slate-300 font-bold">binary.imports</code>: list of dynamic loaded DLL APIs</div>
              <div>• <code className="text-slate-300 font-bold">binary.strings</code>: list of printable system stubs</div>
              <div>• <code className="text-slate-300 font-semibold text-slate-400 mt-1 block">Supported evaluation hooks:</code> <code className="text-cyan-400 bg-slate-950 px-1 py-0.2 rounded text-[8px] font-mono">onDecompile</code>, <code className="text-cyan-400 bg-slate-950 px-1 py-0.2 rounded text-[8px] font-mono">onImportParse</code>, <code className="text-cyan-400 bg-slate-950 px-1 py-0.2 rounded text-[8px] font-mono">onStringSearch</code></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
