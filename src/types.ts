export interface SectionHeader {
  name: string;
  virtualAddress: string;
  virtualSize: string;
  rawSize: string;
  entropy: number;
  characteristics: string[];
}

export interface AssemblyLine {
  address: string;
  opcodes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
  xref?: string;
}

export interface DecompiledFunction {
  name: string;
  address: string;
  arguments: string[];
  returnType: string;
  body: string[];
}

export interface ImportSymbol {
  library: string;
  name: string;
  address: string;
  isSuspicious: boolean;
  reason?: string;
}

export interface ExtractedString {
  address: string;
  value: string;
  length: number;
  type: 'ASCII' | 'Unicode';
  context?: string;
}

export interface HeuristicAnalysis {
  category: 'Suspicious Import' | 'High Entropy Section' | 'Anti-Debugging' | 'Persistence' | 'Network' | 'Evasion';
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: string;
  mitreId?: string;
}

export interface BinaryMetadata {
  fileName: string;
  fileSize: number;
  fileType: 'PE32 Executable (Windows)' | 'ELF 64-bit (Linux)' | 'Mach-O 64-bit (macOS)';
  architecture: 'x86_64' | 'ARM64' | 'x86';
  sha256: string;
  entryPoint: string;
  sections: SectionHeader[];
  imports: ImportSymbol[];
  strings: ExtractedString[];
  assembly: AssemblyLine[];
  decompiledFunctions: DecompiledFunction[];
  heuristics: HeuristicAnalysis[];
  overallEntropy: number;
}

export interface PluginScript {
  id: string;
  name: string;
  description: string;
  author: string;
  version: string;
  code: string;
  targetTrigger: 'onDecompile' | 'onImportParse' | 'onStringSearch' | 'onAnalyze';
  isDefault?: boolean;
}
