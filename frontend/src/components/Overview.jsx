import React from 'react';


export default function Overview({ stats, incidents, onSelectTab, onSelectIncident }) {
  const total = stats?.total_incidents || 0;
  const critical = stats?.critical_incidents || 0;
  const pending = stats?.pending_rotations || 0;
  const resolved = stats?.resolved_incidents || 0;
  const bySeverity = stats?.by_severity || {};
  const byRepo = stats?.by_repository || {};

  // Compute status breakdown from recent incidents
  const statusCounts = incidents.reduce((acc, inc) => {
    acc[inc.status] = (acc[inc.status] || 0) + 1;
    return acc;
  }, {});

  const rotatedCount = statusCounts['rotated'] || 0;

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Incidents */}
        <div className="glass-panel p-5 relative overflow-hidden border border-slate-800 rounded-xl bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Total Leaks Logged</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white tracking-tight">{total}</span>
            <span className="text-xs text-rose-400 font-mono">Deduplicated</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Logged into PostgreSQL audit table</p>
        </div>

        {/* Critical Severity */}
        <div className="glass-panel p-5 relative overflow-hidden border border-slate-800 rounded-xl bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Critical Severity</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-amber-400 tracking-tight">{critical}</span>
            <span className="text-xs text-slate-400 font-mono">Active threats</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Direct credential exposure</p>
        </div>

        {/* Pending Rotations */}
        <div className="glass-panel p-5 relative overflow-hidden border border-slate-800 rounded-xl bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Rotation Queue</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyan-400 tracking-tight">{pending}</span>
            <span className="text-xs text-cyan-300 font-mono">Pending action</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">Needs auto or manual rotation</p>
        </div>

        {/* Rotated & Vault Secured */}
        <div className="glass-panel p-5 relative overflow-hidden border border-slate-800 rounded-xl bg-slate-900/60">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Secured in Vault</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-emerald-400 tracking-tight">{rotatedCount}</span>
            <span className="text-xs text-emerald-300 font-mono">Auto-Rotated</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">KV v2 secrets engine active</p>
        </div>
      </div>

      {/* DevSecOps End-to-End Pipeline Card */}
      <div className="glass-panel p-6 border border-slate-800 rounded-xl bg-slate-900/50">
        <h3 className="text-sm font-semibold text-white tracking-wide flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
          GitOps Secret Shield – End-to-End DevSecOps Architecture Flow
        </h3>
        <p className="text-xs text-slate-400 mt-1">
          Automated multi-layered defense protecting secrets across the entire CI/CD & Git lifecycle.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mt-5">
          {/* Step 1 */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 relative">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1">Layer 1</div>
            <div className="text-xs font-bold text-slate-200">Git Pre-Commit Hook</div>
            <p className="text-[11px] text-slate-400 mt-1">
              TruffleHog Docker + Python regex blocks secrets locally before code is committed.
            </p>
            <span className="inline-block mt-2 text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1.5 py-0.5 rounded font-mono">
              [BLOCKED AT COMMIT]
            </span>
          </div>

          {/* Step 2 */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 relative">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1">Layer 2</div>
            <div className="text-xs font-bold text-slate-200">GitHub Webhook</div>
            <p className="text-[11px] text-slate-400 mt-1">
              HMAC-SHA256 authenticated webhook receives push events, scans diffs & patches.
            </p>
            <span className="inline-block mt-2 text-[10px] bg-cyan-950/60 text-cyan-400 border border-cyan-800/40 px-1.5 py-0.5 rounded font-mono">
              [HMAC SHA-256]
            </span>
          </div>

          {/* Step 3 */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 relative">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1">Layer 3</div>
            <div className="text-xs font-bold text-slate-200">PostgreSQL Audit Log</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Persists unique incident IDs (INC-YYYYMMDD-XXXX), masks secrets, deduplicates events.
            </p>
            <span className="inline-block mt-2 text-[10px] bg-purple-950/60 text-purple-400 border border-purple-800/40 px-1.5 py-0.5 rounded font-mono">
              [DEDUPLICATED AUDIT]
            </span>
          </div>

          {/* Step 4 */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 relative">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1">Layer 4</div>
            <div className="text-xs font-bold text-slate-200">HashiCorp Vault KV v2</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Stores encrypted rotated credentials at secret/data/gitops-secret-shield/...
            </p>
            <span className="inline-block mt-2 text-[10px] bg-amber-950/60 text-amber-400 border border-amber-800/40 px-1.5 py-0.5 rounded font-mono">
              [ENCRYPTED AT REST]
            </span>
          </div>

          {/* Step 5 */}
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 relative">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-1">Layer 5</div>
            <div className="text-xs font-bold text-slate-200">Automated Rotation</div>
            <p className="text-[11px] text-slate-400 mt-1">
              Generates 32-char high entropy passwords, alters DB roles, marks status 'rotated'.
            </p>
            <span className="inline-block mt-2 text-[10px] bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 px-1.5 py-0.5 rounded font-mono">
              [ZERO-TOUCH AUTO]
            </span>
          </div>
        </div>
      </div>

      {/* Two-Column Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity & Incident Breakdown */}
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50">
          <h4 className="text-sm font-semibold text-white mb-4 flex items-center justify-between">
            <span>Threat Severity Distribution</span>
            <span className="text-xs font-mono text-slate-400">Breakdown</span>
          </h4>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1 font-mono">
                <span className="text-rose-400 font-semibold">CRITICAL (High Entropy Keys)</span>
                <span className="text-slate-300">{bySeverity['CRITICAL'] || total} leaks</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-rose-500 h-full rounded-full" style={{ width: '100%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-xs mb-1 font-mono">
                <span className="text-amber-400">HIGH (Tokens / URI Parameters)</span>
                <span className="text-slate-300">{bySeverity['HIGH'] || 0} leaks</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div className="bg-amber-500 h-full rounded-full" style={{ width: '0%' }}></div>
              </div>
            </div>
          </div>

          <div className="mt-6 border-t border-slate-800 pt-4">
            <h5 className="text-xs font-semibold text-slate-300 mb-2">Monitored Repositories</h5>
            {Object.keys(byRepo).length === 0 ? (
              <p className="text-xs text-slate-500">No repositories recorded yet</p>
            ) : (
              <div className="space-y-1.5">
                {Object.entries(byRepo).map(([repo, count]) => (
                  <div key={repo} className="flex justify-between items-center text-xs font-mono bg-slate-950/40 p-2 rounded border border-slate-800">
                    <span className="text-cyan-400">{repo}</span>
                    <span className="bg-slate-800 px-2 py-0.5 rounded text-slate-300 font-bold">{count} incident(s)</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recent Incidents Quick Table */}
        <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm font-semibold text-white">Recent Security Findings</h4>
            <button
              onClick={() => onSelectTab('incidents')}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium transition-colors"
            >
              View All ({incidents.length}) →
            </button>
          </div>

          <div className="space-y-2">
            {incidents.slice(0, 5).map((inc) => (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc)}
                className="p-3 bg-slate-950/60 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 rounded-lg cursor-pointer transition-all flex items-center justify-between"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-white">{inc.incident_id}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {inc.detector_name}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-1">
                    {inc.file_path}:{inc.line_number}
                  </div>
                </div>
                <div className="text-right">
                  <span className={`inline-block text-[10px] font-mono uppercase px-2 py-0.5 rounded font-semibold ${
                    inc.status === 'rotated' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                    inc.remediation_status === 'manual_remediation_required' ? 'bg-purple-950 text-purple-400 border border-purple-800' :
                    'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}>
                    {inc.status}
                  </span>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    {new Date(inc.created_at).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
