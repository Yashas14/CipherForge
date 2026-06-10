import { useState } from 'react';
import { apiPost, formatBytes } from '../lib/api';

export default function BenchmarkTab() {
  const [payloadSize, setPayloadSize] = useState(1024);
  const [iters, setIters] = useState(3);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setResults(null);

    const payload = btoa(
      Array.from(crypto.getRandomValues(new Uint8Array(payloadSize)))
        .map(b => String.fromCharCode(b)).join('')
    );

    const algos = ['aes-gcm', 'chacha20'];
    const out = [];

    for (const algo of algos) {
      let totalEnc = 0, totalDec = 0;
      for (let i = 0; i < iters; i++) {
        try {
          const t0 = performance.now();
          const enc = await apiPost('/encrypt/text', { plaintext: payload, algorithm: algo });
          totalEnc += performance.now() - t0;

          if (enc.metadata?.key) {
            const t1 = performance.now();
            await apiPost('/decrypt/text', { ciphertext: enc.ciphertext, algorithm: algo, key_id: enc.metadata.key });
            totalDec += performance.now() - t1;
          }
        } catch { /* skip */ }
      }
      out.push({
        name: algo === 'aes-gcm' ? 'AES-256-GCM' : 'ChaCha20-Poly1305',
        encMs: totalEnc / iters,
        decMs: totalDec / iters,
      });
    }

    setResults(out);
    setLoading(false);
  };

  const maxTime = results ? Math.max(...results.map(r => Math.max(r.encMs, r.decMs)), 1) : 1;

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">⚡ Performance Benchmark</h2>
      <p className="text-slate-500 text-sm mb-6">Compare algorithm performance with real API calls</p>

      <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6 max-w-3xl">
        <div className="grid grid-cols-2 gap-4 mb-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Payload Size</label>
            <select value={payloadSize} onChange={e => setPayloadSize(+e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:border-blue-500 outline-none transition">
              <option value={100}>100 B (tiny)</option>
              <option value={1024}>1 KB (standard)</option>
              <option value={10240}>10 KB (medium)</option>
              <option value={102400}>100 KB (large)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Iterations</label>
            <input type="number" value={iters} onChange={e => setIters(+e.target.value)} min={1} max={10}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:border-blue-500 outline-none transition" />
          </div>
        </div>

        <button onClick={run} disabled={loading}
          className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg transition disabled:opacity-50">
          {loading ? '⏳ Running Benchmark…' : '⚡ Run Benchmark'}
        </button>

        {results && (
          <div className="mt-6 space-y-5">
            <div className="flex gap-6 text-xs text-slate-400">
              <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-blue-500 inline-block"></span> Encrypt</span>
              <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded bg-emerald-500 inline-block"></span> Decrypt</span>
            </div>

            {results.map((r, i) => {
              const throughput = payloadSize / ((r.encMs + r.decMs) / 1000) / 1024;
              return (
                <div key={i}>
                  <div className="flex justify-between text-sm mb-2">
                    <span className="font-semibold">{r.name}</span>
                    <span className="text-slate-500 font-mono text-xs">{r.encMs.toFixed(1)} + {r.decMs.toFixed(1)} ms · {throughput.toFixed(0)} KB/s</span>
                  </div>
                  <div className="h-6 bg-slate-950 border border-slate-700 rounded-lg overflow-hidden mb-1">
                    <div className="h-full bg-linear-to-r from-blue-500 to-indigo-500 rounded-lg flex items-center px-3 text-[0.65rem] font-bold text-white transition-all duration-700"
                      style={{ width: `${Math.max((r.encMs / maxTime) * 100, 8)}%` }}>
                      {r.encMs.toFixed(1)} ms
                    </div>
                  </div>
                  <div className="h-6 bg-slate-950 border border-slate-700 rounded-lg overflow-hidden">
                    <div className="h-full bg-linear-to-r from-emerald-500 to-teal-500 rounded-lg flex items-center px-3 text-[0.65rem] font-bold text-white transition-all duration-700"
                      style={{ width: `${Math.max((r.decMs / maxTime) * 100, 8)}%` }}>
                      {r.decMs.toFixed(1)} ms
                    </div>
                  </div>
                </div>
              );
            })}

            <div className="text-xs text-slate-500 mt-3">
              Payload: {formatBytes(payloadSize)} · {iters} iterations · Includes network round-trip
            </div>
          </div>
        )}

        {!results && !loading && (
          <div className="text-center text-slate-600 py-12">
            <span className="text-4xl">📊</span>
            <p className="text-sm mt-2">Click Run to compare algorithm performance</p>
          </div>
        )}
      </div>
    </div>
  );
}
