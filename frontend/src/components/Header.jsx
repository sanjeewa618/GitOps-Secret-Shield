import React from 'react';

export default function Header({ health, onRefresh, isRefreshing }) {
  const getStatusColor = (status) => {
    if (status === 'healthy') return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    if (status === 'unreachable') return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
    return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
  };

  return (
    <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-40 px-6 py-4">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-emerald-500/20 border border-emerald-400/40">
            <svg className="w-6 h-6 text-slate-950 font-bold" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold tracking-tight text-white">
                GitOps Secret Shield
              </h1>
              <span className="text-[10px] font-mono uppercase tracking-wider bg-emerald-950/80 text-emerald-400 border border-emerald-500/40 px-2 py-0.5 rounded-full font-semibold">
                DevSecOps
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Automated Secret Detection, PostgreSQL Audit Logging & Vault Auto-Rotation
            </p>
          </div>
        </div>

        {/* Live Service Health Badges */}
        <div className="flex items-center flex-wrap gap-2.5">
          {/* FastAPI */}
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${getStatusColor(health.backend)}`}>
            <span className={`w-2 h-2 rounded-full ${health.backend === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
            <span>API: {health.backend}</span>
          </div>

          {/* PostgreSQL */}
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${getStatusColor(health.postgres)}`}>
            <span className={`w-2 h-2 rounded-full ${health.postgres === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
            <span>PostgreSQL: 5434</span>
          </div>

          {/* HashiCorp Vault */}
          <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${getStatusColor(health.vault)}`}>
            <span className={`w-2 h-2 rounded-full ${health.vault === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
            <span>Vault: 8200 {health.vaultVersion ? `(v${health.vaultVersion})` : ''}</span>
          </div>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <svg
              className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-emerald-400' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </button>
        </div>
      </div>
    </header>
  );
}
