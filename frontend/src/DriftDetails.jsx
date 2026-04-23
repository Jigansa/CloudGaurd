import React from 'react';

export default function DriftDetails() {
  const diffData = {
    added: ["+ Rule: Ingress 0.0.0.0/0 on Port 22 (SSH)", "+ Tag: Project=NotSet (Shadow IT)"],
    removed: ["- Rule: Ingress 10.0.0.0/8 on Port 22 (Corporate VPN)"]
  };

  return (
    <div className="cloud-card animate-fade-in border border-indigo-500/30 shadow-[0_0_30px_rgba(99,102,241,0.15)] relative overflow-hidden">
      {/* Decorative gradient flare */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/10 rounded-full blur-[80px] -z-10 pointer-events-none"></div>

      <div className="flex items-center justify-between mb-4 relative z-10">
        <h3 className="text-xl font-bold text-white flex items-center gap-2">
          <span className="text-indigo-400 text-2xl">⏳</span> The Time Machine 
        </h3>
        <span className="text-[10px] text-indigo-300 font-mono bg-indigo-500/20 border border-indigo-500/30 px-3 py-1 rounded-full uppercase tracking-wider">
          SQL Database state diff view
        </span>
      </div>
      <p className="text-sm text-slate-400 mb-6 relative z-10">
        Historical configuration drift detected since yesterday's snapshot.
      </p>

      <div className="bg-black/50 backdrop-blur-md rounded-xl p-0 overflow-hidden border border-white/10 font-mono text-sm relative z-10">
        <div className="bg-gradient-to-r from-white/10 to-transparent px-4 py-3 text-[11px] text-slate-300 tracking-[0.2em] font-semibold border-b border-white/5 flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>
          SECURITY GROUP DELTA (sg-0x9876dummy4321)
        </div>
        <div className="p-5 space-y-3 relative">
          {diffData.removed.map((line, i) => (
             <div key={`rem-${i}`} className="flex items-center gap-3 text-rose-300 bg-rose-950/40 px-4 py-2.5 rounded-lg border-l-4 border-rose-500 shadow-inner">
               <span className="font-bold text-rose-500 text-lg">-</span> {line}
             </div>
          ))}
          {diffData.added.map((line, i) => (
             <div key={`add-${i}`} className="flex items-center gap-3 text-emerald-300 bg-emerald-950/40 px-4 py-2.5 rounded-lg border-l-4 border-emerald-500 shadow-inner">
               <span className="font-bold text-emerald-500 text-lg">+</span> {line}
             </div>
          ))}
        </div>
      </div>
    </div>
  );
}
