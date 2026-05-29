import React, { useState } from 'react';

interface HexViewerProps {
  sha256: string;
  fileSize: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({ sha256, fileSize }) => {
  const [hoveredOffset, setHoveredOffset] = useState<number | null>(null);

  // Generate deterministic pseudo-random hex bytes based on the file's hash
  const getHexBytes = () => {
    const bytes: string[] = [];
    const hashChars = sha256 + "abcdef0123456789";
    for (let i = 0; i < 256; i++) {
      const charIndex1 = (i * 3 + 7) % hashChars.length;
      const charIndex2 = (i * 7 + 13) % hashChars.length;
      const byte = hashChars[charIndex1] + hashChars[charIndex2];
      bytes.push(byte.toUpperCase());
    }
    return bytes;
  };

  const bytes = getHexBytes();
  const rows = 16;
  const columns = 16;

  // Convert hex values to printable ASCII representations
  const getAsciiChar = (hexStr: string) => {
    const code = parseInt(hexStr, 16);
    if (code >= 32 && code <= 126) {
      return String.fromCharCode(code);
    }
    return '.';
  };

  return (
    <div className="bg-slate-950 p-3 rounded-md border border-slate-800">
      <div className="flex justify-between items-center mb-2.5 border-b border-slate-800 pb-2">
        <div>
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">Linear Hex Dumper</h3>
          <p className="text-[11px] text-slate-500 font-mono font-bold">Hover over segments to resolve physical offset maps.</p>
        </div>
        <div className="text-[10px] font-mono bg-slate-900 border border-slate-850 text-cyan-400 px-2 py-0.5 rounded font-bold">
          OFFSET BASE: 0x00000000
        </div>
      </div>

      <div className="overflow-x-auto">
        <div className="min-w-[650px] font-mono text-xs leading-relaxed select-none">
          {/* Header offset index line */}
          <div className="flex text-slate-500 border-b border-slate-800 pb-1 mb-1.5">
            <div className="w-20 text-slate-500 font-bold">Offset</div>
            <div className="flex-1 flex gap-1.5 px-4 font-bold">
              {Array.from({ length: columns }).map((_, i) => (
                <div key={i} className="w-6 text-center text-slate-500">
                  {i.toString(16).toUpperCase().padStart(2, '0')}
                </div>
              ))}
            </div>
            <div className="w-40 text-left pl-3 text-slate-500 font-bold">ASCII Translation</div>
          </div>

          {/* Matrix body */}
          <div className="space-y-0.5">
            {Array.from({ length: rows }).map((_, rowIndex) => {
              const rowOffset = rowIndex * columns;
              return (
                <div key={rowIndex} className="flex hover:bg-slate-900/50 py-0.5 rounded transition">
                  {/* Offset indicator */}
                  <div className="w-20 text-cyan-400 font-semibold font-mono">
                    {rowOffset.toString(16).toUpperCase().padStart(8, '0')}
                  </div>

                  {/* Hex bytes section */}
                  <div className="flex-1 flex gap-1.5 px-4 text-slate-300">
                    {Array.from({ length: columns }).map((_, colIndex) => {
                      const absoluteIndex = rowOffset + colIndex;
                      const byte = bytes[absoluteIndex % bytes.length];
                      const isHovered = hoveredOffset === absoluteIndex;
                      
                      // Colorize special bytes (e.g. zero values, executable files, EOF marker patterns)
                      let byteColorClass = "text-slate-300";
                      if (byte === "00") {
                        byteColorClass = "text-slate-600";
                      } else if (byte === "FF" || byte === "EB" || byte === "90") {
                        byteColorClass = "text-amber-400 font-semibold"; // suspicious executable opcodes
                      } else if (parseInt(byte, 16) > 127) {
                        byteColorClass = "text-cyan-400";
                      }

                      return (
                        <div
                          key={colIndex}
                          onMouseEnter={() => setHoveredOffset(absoluteIndex)}
                          onMouseLeave={() => setHoveredOffset(null)}
                          className={`w-6 text-center cursor-crosshair transition rounded-sm ${byteColorClass} ${
                            isHovered ? 'bg-cyan-500/30 text-white font-bold scale-110' : ''
                          }`}
                          title={`Byte Offset: 0x${absoluteIndex.toString(16).toUpperCase()}`}
                        >
                          {byte}
                        </div>
                      );
                    })}
                  </div>

                  {/* Character conversion output segment segment */}
                  <div className="w-40 text-left pl-3 text-emerald-500/80 tracking-wide font-mono flex">
                    {Array.from({ length: columns }).map((_, colIndex) => {
                      const absoluteIndex = rowOffset + colIndex;
                      const byte = bytes[absoluteIndex % bytes.length];
                      const isHovered = hoveredOffset === absoluteIndex;
                      const char = getAsciiChar(byte);
                      return (
                        <span 
                          key={colIndex} 
                          className={`${isHovered ? 'bg-cyan-500/40 text-white font-bold px-0.5 rounded-sm' : ''}`}
                        >
                          {char}
                        </span>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="mt-3.5 flex flex-wrap justify-between items-center pt-2.5 border-t border-slate-800 text-[10px] text-slate-500 font-mono">
        <div className="flex gap-4">
          <span className="flex items-center gap-1 font-semibold">
            <span className="w-2 h-2 bg-slate-600 rounded-sm inline-block"></span>
            Null Bytes (00)
          </span>
          <span className="flex items-center gap-1 font-semibold">
            <span className="w-2 h-2 bg-amber-400 rounded-sm inline-block"></span>
            Interrupt Opcodes (90/FF)
          </span>
          <span className="flex items-center gap-1 font-semibold">
            <span className="w-2 h-2 bg-cyan-400 rounded-sm inline-block"></span>
            High bits (&gt;127)
          </span>
        </div>
        {hoveredOffset !== null && (
          <span className="text-cyan-400 font-bold bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-850">
            Focused byte offset: 0x{hoveredOffset.toString(16).toUpperCase().padStart(4, '0')} (Dec: {hoveredOffset})
          </span>
        )}
      </div>
    </div>
  );
};
