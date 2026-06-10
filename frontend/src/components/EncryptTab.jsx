import { useState } from 'react';
import { apiPost, b64encode, b64decode } from '../lib/api';

const ALGOS = [
  { value: 'aes-gcm', label: 'AES-256-GCM' },
  { value: 'chacha20', label: 'ChaCha20-Poly1305' },
  { value: 'rsa-oaep', label: 'RSA-4096-OAEP' },
  { value: 'hybrid', label: 'Hybrid (RSA + AES-256)' },
  { value: 'ecdh', label: 'X25519-ECDH' },
];

export default function EncryptTab({ keys, incOps }) {
  const [mode, setMode] = useState('encrypt');
  const [algo, setAlgo] = useState('aes-gcm');
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [decKey, setDecKey] = useState('');
  const [aad, setAad] = useState('');
  const [output, setOutput] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    setOutput(null);
    try {
      const t0 = performance.now();

      if (mode === 'encrypt') {
        if (!plaintext.trim()) { setOutput({ error: 'Enter plaintext first' }); return; }
        const body = { plaintext: b64encode(plaintext), algorithm: algo, aad: aad ? b64encode(aad) : null };
        if (['rsa-oaep', 'hybrid'].includes(algo)) {
          if (!keys.rsa) { setOutput({ error: 'Generate RSA keys first (Key Workshop)' }); return; }
          body.recipient_public_key = keys.rsa.pubPem;
        } else if (algo === 'ecdh') {
          if (!keys.ecdh) { setOutput({ error: 'Generate X25519 keys first (Key Workshop)' }); return; }
          body.recipient_public_key = keys.ecdh.pubB64;
        }

        const data = await apiPost('/encrypt/text', body);
        const elapsed = (performance.now() - t0).toFixed(1);
        incOps();
        setOutput({ success: true, ciphertext: data.ciphertext, key: data.metadata?.key, elapsed });
      } else {
        if (!ciphertext.trim()) { setOutput({ error: 'Paste ciphertext first' }); return; }
        const body = { ciphertext: ciphertext.trim(), algorithm: algo, aad: aad ? b64encode(aad) : null };

        if (['aes-gcm', 'chacha20'].includes(algo)) {
          if (!decKey.trim()) { setOutput({ error: 'Decryption key required' }); return; }
          body.key_id = decKey.trim();
        } else if (['rsa-oaep', 'hybrid'].includes(algo)) {
          if (!keys.rsa) { setOutput({ error: 'No RSA private key' }); return; }
          body.private_key = keys.rsa.privPem;
        } else if (algo === 'ecdh') {
          if (!keys.ecdh) { setOutput({ error: 'No X25519 private key' }); return; }
          body.private_key = keys.ecdh.privB64;
        }

        const data = await apiPost('/decrypt/text', body);
        const elapsed = (performance.now() - t0).toFixed(1);
        incOps();
        let pt;
        try { pt = b64decode(data.plaintext); } catch { pt = atob(data.plaintext); }
        setOutput({ success: true, plaintext: pt, elapsed });
      }
    } catch (err) {
      setOutput({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">🔐 Encrypt & Decrypt</h2>
      <p className="text-slate-500 text-sm mb-6">Transform text with military-grade encryption algorithms</p>

      <div className="grid grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5 pb-3 border-b border-slate-800">
            <h3 className="font-semibold">Input</h3>
            <div className="flex bg-slate-800 rounded-lg p-0.5">
              {['encrypt', 'decrypt'].map(m => (
                <button key={m} onClick={() => setMode(m)}
                  className={`px-4 py-1.5 text-xs font-semibold rounded-md transition ${mode === m ? 'bg-blue-500 text-white' : 'text-slate-400'}`}>
                  {m === 'encrypt' ? 'Encrypt' : 'Decrypt'}
                </button>
              ))}
            </div>
          </div>

          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Algorithm</label>
          <select value={algo} onChange={e => setAlgo(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-4 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 outline-none transition">
            {ALGOS.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
          </select>

          {mode === 'encrypt' ? (
            <>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Plaintext</label>
              <textarea value={plaintext} onChange={e => setPlaintext(e.target.value)} rows={5}
                placeholder="Enter text to encrypt…"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm font-mono resize-y mb-4 focus:border-blue-500 outline-none transition" />
            </>
          ) : (
            <>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Ciphertext (Base64)</label>
              <textarea value={ciphertext} onChange={e => setCiphertext(e.target.value)} rows={5}
                placeholder="Paste Base64 ciphertext…"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm font-mono resize-y mb-4 focus:border-blue-500 outline-none transition" />
              {['aes-gcm', 'chacha20'].includes(algo) && (
                <>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Decryption Key (Base64)</label>
                  <input type="password" value={decKey} onChange={e => setDecKey(e.target.value)}
                    placeholder="Paste the key"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-4 focus:border-blue-500 outline-none transition" />
                </>
              )}
            </>
          )}

          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">AAD (Optional)</label>
          <input type="text" value={aad} onChange={e => setAad(e.target.value)} placeholder="Additional Authenticated Data"
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-5 focus:border-blue-500 outline-none transition" />

          <button onClick={run} disabled={loading}
            className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 hover:from-blue-400 hover:to-indigo-400 text-white shadow-lg shadow-blue-500/20 transition disabled:opacity-50">
            {loading ? '⏳ Processing…' : '🚀 Execute'}
          </button>
        </div>

        {/* Output Panel */}
        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5 pb-3 border-b border-slate-800">
            <h3 className="font-semibold">Output</h3>
            {output?.ciphertext && (
              <button onClick={() => navigator.clipboard.writeText(output.ciphertext)}
                className="text-xs text-slate-400 hover:text-blue-400 transition">📋 Copy</button>
            )}
          </div>

          <div className="bg-slate-950 border border-slate-700 rounded-lg p-4 min-h-62.5 font-mono text-xs break-all overflow-y-auto max-h-100">
            {!output && <div className="flex flex-col items-center justify-center h-full text-slate-600 text-center py-12"><span className="text-4xl mb-2">🔒</span><p>Run an operation to see results</p></div>}
            {output?.error && <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 font-sans text-sm">❌ {output.error}</div>}
            {output?.ciphertext && (
              <>
                <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-sans font-semibold mb-1">Ciphertext</div>
                <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 mb-3 text-slate-300">{output.ciphertext}</div>
                {output.key && (
                  <>
                    <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-sans font-semibold mb-1">🔑 Decryption Key — Save This!</div>
                    <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mb-3 text-amber-300">{output.key}</div>
                  </>
                )}
                <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-sans text-sm font-semibold">
                  ✅ Encrypted in {output.elapsed} ms
                </div>
              </>
            )}
            {output?.plaintext && (
              <>
                <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-sans font-semibold mb-1">Decrypted Plaintext</div>
                <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3 mb-3 text-slate-200">{output.plaintext}</div>
                <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-sans text-sm font-semibold">
                  ✅ Decrypted in {output.elapsed} ms
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
