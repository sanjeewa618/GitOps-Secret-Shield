import React, { useState, useEffect } from 'react';
import { api, getStoredToken } from '../services/api';

export default function IntelligencePanel({ onRefreshIncidents }) {
  const [user, setUser] = useState(null);
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState(null);

  const [historyFindings, setHistoryFindings] = useState([]);
  const [correlationGroups, setCorrelationGroups] = useState([]);
  const [fpRules, setFpRules] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState(null);
  const [loading, setLoading] = useState(true);

  // New FP Rule form
  const [fpDetector, setFpDetector] = useState('');
  const [fpFilePattern, setFpFilePattern] = useState('');
  const [fpFingerprint, setFpFingerprint] = useState('');
  const [fpReason, setFpReason] = useState('');
  const [fpDays, setFpDays] = useState(30);
  const [fpMsg, setFpMsg] = useState(null);

  const loadAll = async () => {
    setLoading(true);
    try {
      if (getStoredToken()) {
        try {
          const me = await api.getMe();
          setUser(me);
        } catch {
          api.logout();
          setUser(null);
        }
      }
      const [hist, corr, rules] = await Promise.all([
        api.getGitHistoryFindings().catch(() => ({ findings: [] })),
        api.getCorrelationGroups().catch(() => ({ groups: [] })),
        api.getFalsePositives().catch(() => ({ rules: [] })),
      ]);
      setHistoryFindings(hist.findings || []);
      setCorrelationGroups(corr.groups || []);
      setFpRules(rules.rules || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError(null);
    try {
      const res = await api.login(username, password);
      setUser({ username, role: res.role, authenticated: true });
      setPassword('');
    } catch (err) {
      setAuthError(err.message);
    }
  };

  const handleLogout = () => {
    api.logout();
    setUser(null);
  };

  const handleScanHistory = async () => {
    setIsScanning(true);
    setScanMsg(null);
    try {
      const res = await api.scanGitHistory({ max_commits: 25 });
      setScanMsg({
        ok: true,
        text: `Scanned ${res.commits_scanned} commits — ${res.findings_count} historical finding(s).`,
      });
      await loadAll();
    } catch (err) {
      setScanMsg({ ok: false, text: err.message });
    } finally {
      setIsScanning(false);
    }
  };

  const handleCreateRule = async (e) => {
    e.preventDefault();
    setFpMsg(null);
    try {
      await api.createFalsePositiveRule({
        secret_fingerprint: fpFingerprint || null,
        detector_name: fpDetector || null,
        file_path_pattern: fpFilePattern || null,
        reason: fpReason,
        expires_in_days: Number(fpDays) || 30,
      });
      setFpDetector('');
      setFpFilePattern('');
      setFpFingerprint('');
      setFpReason('');
      setFpMsg({ ok: true, text: 'Scoped false-positive rule created with expiration.' });
      await loadAll();
      if (onRefreshIncidents) onRefreshIncidents();
    } catch (err) {
      setFpMsg({ ok: false, text: err.message });
    }
  };

  const handleDeactivateRule = async (ruleId) => {
    try {
      await api.deactivateFalsePositiveRule(ruleId);
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="space-y-6">
      {/* RBAC Authentication Bar */}
      <div className="glass-panel p-4 border border-slate-800 rounded-xl bg-slate-900/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <span>🔐</span> RBAC Session (Required for Admin Actions)
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            {user
              ? `Signed in as ${user.username} (${user.role.toUpperCase()})`
              : 'Sign in as admin to run Git history scans, approve remediations, or manage false-positive rules.'}
          </p>
        </div>

        {user ? (
          <button
            onClick={handleLogout}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono"
          >
            Sign Out ({user.username})
          </button>
        ) : (
          <form onSubmit={handleLogin} className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 w-28"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 w-36"
            />
            <button
              type="submit"
              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded-lg"
            >
              Sign In
            </button>
            {authError && <span className="text-xs text-rose-400 font-mono">{authError}</span>}
          </form>
        )}
      </div>

      {/* Git History Leak Investigation */}
      <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>🕰️</span> Git History Leak Investigation
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Scans historical commits for exposed credentials using masked values & SHA-256 fingerprints. Removing from Git history does not revoke a credential.
            </p>
          </div>
          <button
            onClick={handleScanHistory}
            disabled={isScanning}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs rounded-lg transition-colors disabled:opacity-50 whitespace-nowrap"
          >
            {isScanning ? 'Scanning History...' : 'Scan Git History (Last 25 Commits)'}
          </button>
        </div>

        {scanMsg && (
          <div className={`p-3 rounded-lg text-xs font-mono ${scanMsg.ok ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-500/30' : 'bg-rose-950/60 text-rose-300 border border-rose-500/30'}`}>
            {scanMsg.text}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-mono text-slate-400 uppercase">
                <th className="py-2.5 px-3">Commit</th>
                <th className="py-2.5 px-3">Detector</th>
                <th className="py-2.5 px-3">Masked / Fingerprint</th>
                <th className="py-2.5 px-3">File</th>
                <th className="py-2.5 px-3">Risk</th>
                <th className="py-2.5 px-3">Linked Incident</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr><td colSpan={6} className="py-6 text-center text-slate-500">Loading history findings...</td></tr>
              ) : historyFindings.length === 0 ? (
                <tr><td colSpan={6} className="py-6 text-center text-slate-500 font-sans">No historical leaks recorded yet. Run a Git history scan (requires admin sign-in).</td></tr>
              ) : (
                historyFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-cyan-400">{f.commit_sha?.slice(0, 8)}</td>
                    <td className="py-2.5 px-3 text-slate-200">{f.detector_name}</td>
                    <td className="py-2.5 px-3">
                      <span className="text-rose-400">{f.secret_masked}</span>
                      <div className="text-[10px] text-slate-500">fp:{f.secret_fingerprint?.slice(0, 12)}</div>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">{f.file_path}:{f.line_number}</td>
                    <td className="py-2.5 px-3 text-amber-400 font-bold">{f.risk_score} ({f.severity})</td>
                    <td className="py-2.5 px-3 text-emerald-400">{f.linked_incident_id || 'Unlinked'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Correlation Groups */}
      <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <span>🔗</span> Correlated Incident Groups ({correlationGroups.length})
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {correlationGroups.slice(0, 8).map((g) => (
            <div key={g.correlation_group_id} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 font-mono text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-emerald-400 font-bold">{g.correlation_group_id}</span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 text-[10px]">
                  {g.occurrence_count} occurrence(s)
                </span>
              </div>
              <div className="text-slate-300">{g.repository} · {g.detector_name}</div>
              <div className="text-[10px] text-slate-500">
                Incidents: {g.incident_ids.join(', ')}
              </div>
            </div>
          ))}
          {correlationGroups.length === 0 && (
            <div className="text-xs text-slate-500 col-span-2">No correlated groups yet.</div>
          )}
        </div>
      </div>

      {/* False Positive Management */}
      <div className="glass-panel p-5 border border-slate-800 rounded-xl bg-slate-900/50 space-y-4">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span>✅</span> False-Positive Allowlist Rules (Time-Bound & Scoped)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Rules must target a specific fingerprint or detector + file path pattern and always expire automatically.
          </p>
        </div>

        <form onSubmit={handleCreateRule} className="grid grid-cols-1 sm:grid-cols-5 gap-2.5">
          <input
            type="text"
            value={fpFingerprint}
            onChange={(e) => setFpFingerprint(e.target.value)}
            placeholder="Fingerprint (optional)"
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
          />
          <input
            type="text"
            value={fpDetector}
            onChange={(e) => setFpDetector(e.target.value)}
            placeholder="Detector (e.g. High Entropy Secret)"
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
          />
          <input
            type="text"
            value={fpFilePattern}
            onChange={(e) => setFpFilePattern(e.target.value)}
            placeholder="File pattern (e.g. docs/sample)"
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
          />
          <input
            type="text"
            value={fpReason}
            onChange={(e) => setFpReason(e.target.value)}
            placeholder="Reason (required)"
            required
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
          />
          <div className="flex gap-2">
            <input
              type="number"
              min="1"
              max="365"
              value={fpDays}
              onChange={(e) => setFpDays(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs font-mono text-slate-200 w-16"
              title="Expires in days"
            />
            <button
              type="submit"
              className="flex-1 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs rounded"
            >
              Add Rule
            </button>
          </div>
        </form>

        {fpMsg && (
          <div className={`p-2.5 rounded text-xs font-mono ${fpMsg.ok ? 'bg-emerald-950/60 text-emerald-300' : 'bg-rose-950/60 text-rose-300'}`}>
            {fpMsg.text}
          </div>
        )}

        <div className="space-y-2">
          {fpRules.map((r) => (
            <div key={r.id} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between text-xs font-mono">
              <div>
                <span className="text-emerald-400 font-bold">Rule #{r.id}</span>
                <span className="text-slate-300 ml-2">
                  {r.secret_fingerprint ? `fp:${r.secret_fingerprint.slice(0, 12)}` : `${r.detector_name} @ ${r.file_path_pattern}`}
                </span>
                <div className="text-[11px] text-slate-400 font-sans mt-0.5">
                  Reason: {r.reason} · Expires: {new Date(r.expires_at).toLocaleDateString()} · By: {r.created_by}
                </div>
              </div>
              <button
                onClick={() => handleDeactivateRule(r.id)}
                className="px-2.5 py-1 bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-[11px]"
              >
                Deactivate
              </button>
            </div>
          ))}
          {fpRules.length === 0 && (
            <div className="text-xs text-slate-500">No active false-positive allowlist rules.</div>
          )}
        </div>
      </div>
    </div>
  );
}
