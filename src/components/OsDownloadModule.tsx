import React, { useState } from 'react';
import { Download, Monitor, ShieldCheck, Cpu, HardDrive, Terminal, CheckCircle2 } from 'lucide-react';

interface InstallerMetadata {
  platform: 'windows' | 'linux' | 'macos';
  title: string;
  sub: string;
  version: string;
  size: string;
  format: string;
  sha256: string;
  command?: string;
}

export const OsDownloadModule: React.FC = () => {
  const [activePlatform, setActivePlatform] = useState<'windows' | 'macos' | 'linux'>('windows');
  const [downloading, setDownloading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [downloadCompleted, setDownloadCompleted] = useState(false);

  const installers: { [key in 'windows' | 'macos' | 'linux']: InstallerMetadata } = {
    windows: {
      platform: 'windows',
      title: 'Aegis Binary Studio for Windows',
      sub: 'Compatible with Windows 10 & 11 (64-bit architectures)',
      version: 'v4.2.1-LTS Stable Release',
      size: '64.2 MB',
      format: 'Portable Executable & MSI Installer package',
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    },
    macos: {
      platform: 'macos',
      title: 'Aegis Binary Studio for macOS',
      sub: 'Universal binary supporting Apple Silicon (M1/M2/M3) & Intel Core',
      version: 'v4.2.1-LTS Stable Release',
      size: '72.8 MB',
      format: 'Self-contained Disk Image (DMG) bundle',
      sha256: '7ca97072f883da4c8f5f4ba2c08ecba30176df912a20e4bbfbb1e58f04bc1220'
    },
    linux: {
      platform: 'linux',
      title: 'Aegis Binary Studio for GNU/Linux',
      sub: 'Tested on Ubuntu 20.04+, Debian 11+, Fedora 38+, Arch Linux',
      version: 'v4.2.1-LTS Stable Release',
      size: '58.9 MB',
      format: 'AppImage static release, Debian/RPM native packages',
      sha256: '5eb10ec0bc1da1a6b097daea01a6b097daea01bcffabec01b87a91faee1ebd82'
    }
  };

  const selectedInstaller = installers[activePlatform];

  const handleDownloadTrigger = () => {
    setDownloading(true);
    setProgress(0);
    setDownloadCompleted(false);

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setDownloading(false);
          setDownloadCompleted(true);
          return 100;
        }
        return prev + 10;
      });
    }, 150);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-md overflow-hidden shadow-xl font-sans">
      <div className="p-3.5 border-b border-slate-800 bg-slate-950 flex flex-wrap justify-between items-center gap-4">
        <div>
          <h3 className="text-xs font-bold text-slate-100 flex items-center gap-1.5 font-mono uppercase tracking-wider">
            <Monitor className="text-cyan-400 w-4 h-4" />
            Download Aegis Client Desktop Studio
          </h3>
          <p className="text-[11px] text-slate-500 font-mono">Run high-performance native decompilations offline with zero server overhead.</p>
        </div>
        <div className="flex bg-slate-900 p-0.5 rounded border border-slate-800">
          {(['windows', 'macos', 'linux'] as const).map((platform) => (
            <button
              key={platform}
              onClick={() => {
                setActivePlatform(platform);
                setDownloadCompleted(false);
                setProgress(0);
              }}
              className={`px-2.5 py-0.5 text-[10px] font-bold font-mono uppercase rounded transition cursor-pointer ${
                activePlatform === platform
                  ? 'bg-cyan-600 text-white shadow-md'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {platform}
            </button>
          ))}
        </div>
      </div>

      <div className="p-3.5 grid grid-cols-1 md:grid-cols-12 gap-3.5 items-center">
        {/* Core Detail */}
         <div className="md:col-span-7 space-y-3">
          <div className="space-y-0.5">
            <h4 className="text-sm font-bold text-slate-100 tracking-tight font-sans">{selectedInstaller.title}</h4>
            <p className="text-[11px] text-slate-400 leading-normal font-mono">{selectedInstaller.sub}</p>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
            <div className="bg-slate-950 p-2 rounded border border-slate-800/60 space-y-0.5">
              <span className="text-slate-500 block text-[9px] uppercase tracking-wider font-bold">Release Version</span>
              <span className="text-cyan-400 font-bold">{selectedInstaller.version}</span>
            </div>
            <div className="bg-slate-950 p-2 rounded border border-slate-800/60 space-y-0.5">
              <span className="text-slate-500 block text-[9px] uppercase tracking-wider font-bold">Installer Size</span>
              <span className="text-emerald-400 font-bold">{selectedInstaller.size}</span>
            </div>
            <div className="bg-slate-950 p-2 rounded border border-slate-800/60 space-y-0.5 col-span-2">
              <span className="text-slate-500 block text-[9px] uppercase tracking-wider font-bold">Cryptographic Hash (SHA-256 Verification)</span>
              <span className="text-slate-400 whitespace-nowrap block overflow-x-auto text-[9px] select-all cursor-pointer scrollbar-thin">
                {selectedInstaller.sha256}
              </span>
            </div>
          </div>

          {/* Quick installation stubs */}
          <div className="p-2.5 bg-slate-950/70 border border-slate-805 rounded space-y-1.5">
            <div className="flex items-center gap-1 text-[10px] font-bold text-slate-300 font-mono uppercase tracking-wider">
              <Terminal className="text-cyan-400 w-3.5 h-3.5" />
              <span>Developer CLI Package install command</span>
            </div>
            <div className="bg-black/90 p-2 rounded font-mono text-[11px] text-cyan-400 flex justify-between items-center overflow-x-auto border border-slate-800">
              <code className="text-emerald-400">
                {activePlatform === 'windows' && `winget install --id Aegis.BinaryStudio.LTS`}
                {activePlatform === 'macos' && `brew install --cask aegis-binary-studio`}
                {activePlatform === 'linux' && `sudo apt-get install aegis-binary-studio`}
              </code>
              <span className="text-[8px] bg-slate-900 text-slate-500 font-bold px-1.5 py-0.2 rounded border border-slate-850">
                STABLE
              </span>
            </div>
          </div>
        </div>

        {/* Action down installer module */}
        <div className="md:col-span-5 flex flex-col justify-center items-center bg-slate-950/40 p-4.5 rounded border border-slate-800/50 space-y-3">
          <div className="relative p-3.5 bg-slate-900 border border-slate-800 rounded-full text-cyan-400">
            <Download className="w-6 h-6 animate-pulse" />
          </div>

          <div className="text-center space-y-0.5">
            <span className="text-[11px] font-bold text-slate-300 block font-mono">{selectedInstaller.format}</span>
            <span className="text-[10px] text-slate-500 block">Verified package containing visual reverse engine dependencies</span>
          </div>

          {downloading ? (
            <div className="w-full space-y-1.5">
              <div className="flex justify-between items-center text-[10px] font-mono">
                <span className="text-slate-400">Downloading package...</span>
                <span className="text-cyan-400 font-bold">{progress}%</span>
              </div>
              <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyan-500 rounded-full transition-all duration-150" 
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          ) : downloadCompleted ? (
            <div className="w-full text-center space-y-2 bg-cyan-950/20 p-3 border border-cyan-800/40 rounded">
              <div className="flex justify-center items-center gap-1 text-[11px] text-cyan-300 font-bold uppercase tracking-wider font-mono">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Download Initiated!</span>
              </div>
              <p className="text-[10px] text-slate-400 leading-normal font-mono">Double-click the downloaded executable package to register Aegis Client modules.</p>
              <button 
                onClick={() => setDownloadCompleted(false)}
                className="text-[10px] text-cyan-400 hover:text-cyan-300 hover:underline font-bold block mx-auto cursor-pointer font-mono uppercase"
              >
                Reset trigger
              </button>
            </div>
          ) : (
            <button
              onClick={handleDownloadTrigger}
              className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-1.5 px-3 rounded text-[11px] gap-1.5 flex items-center justify-center cursor-pointer transition font-mono uppercase"
            >
              <Download className="w-3.5 h-3.5" />
              Download LTS Package
            </button>
          )}

          <div className="flex items-center gap-1 text-[9px] text-slate-500 font-mono text-center">
            <ShieldCheck className="w-3 h-3 text-cyan-500" />
            <span>Fully compiled & signed GPG binaries</span>
          </div>
        </div>
      </div>
    </div>
  );
};
