import { useState } from 'react';
import { apiPost } from '../lib/api';

const ALGO_OPTIONS = [
  { value: 'aes-256', label: 'AES-256 (Symmetric)' },
  { value: 'chacha20', label: 'ChaCha20 (Symmetric)' },
  { value: 'rsa-4096', label: 'RSA-4096 (Asymmetric)' },
  { value: 'x25519', label: 'X25519 (Key Agreement)' },
  { value: 'fernet', label: 'Fernet (Token Encryption)' },
];

export default function KeysTab({ keys, setKeys }) {
  const [algo, setAlgo] = useState('aes-256');
  const [output, setOutput] = useState(null);
  const [loading, setLoading] = useState(false);
  const [generated, setGenerated] = useState([]);

  const generate = async () => {
    setLoading(true); setOutput(null);
    try {
      const t0 = performance.now();
      const data = await apiPost('/keys/generate', { algorithm: algo });
      const elapsed = (performance.now() - t0).toFixed(1);

      const entry = { type: algo.toUpperCase(), id: data.key_id, publicKey: data.public_key, elapsed };
      setGenerated(prev => [entry, ...prev]);

      if (algo === 'rsa-4096' && data.public_key) {
        setKeys(prev => ({ ...prev, rsa: { pubPem: data.public_key, privPem: null } }));
      } else if (algo === 'x25519' && data.public_key) {
        setKeys(prev => ({ ...prev, ecdh: { pubB64: data.public_key, privB64: null } }));
      }

      setOutput({ success: true, data, elapsed });
    } catch (err) { setOutput({ error: err.message }); }
    finally { setLoading(false); }
  };

  const generateRSAFull = async () => {
    setLoading(true); setOutput(null);
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['sign', 'verify']
      );
      const privBuf = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const pubBuf = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const toPem = (buf, type) => {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
        return `-----BEGIN ${type} KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${type} KEY-----`;
      };
      const privPem = toPem(privBuf, 'PRIVATE');
      const pubPem = toPem(pubBuf, 'PUBLIC');
      setKeys(prev => ({ ...prev, rsa: { privPem, pubPem } }));
      setGenerated(prev => [{ type: 'RSA-4096 (FULL)', id: 'browser-generated', publicKey: pubPem.substring(0, 80) + '…', elapsed: 'N/A' }, ...prev]);
      setOutput({ success: true, rsaFull: true, pubPem });
    } catch (err) { setOutput({ error: err.message }); }
    finally { setLoading(false); }
  };

  const clearAll = () => {
    setKeys({ rsa: null, ecdh: null, symmetric: [] });
    setGenerated([]);
    setOutput(null);
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">🔑 Key Workshop</h2>
      <p className="text-slate-500 text-sm mb-6">Generate, manage, and inspect cryptographic keys</p>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <h3 className="font-semibold mb-5 pb-3 border-b border-slate-800">Generate Key</h3>
          <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Key Type</label>
          <select value={algo} onChange={e => setAlgo(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-4 focus:border-blue-500 outline-none transition">
            {ALGO_OPTIONS.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
          </select>

          <button onClick={generate} disabled={loading}
            className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg transition disabled:opacity-50 mb-3">
            {loading ? '⏳ Generating…' : '🔑 Generate Key'}
          </button>

          <button onClick={generateRSAFull} disabled={loading}
            className="w-full py-3 rounded-lg font-bold text-sm border border-slate-700 text-slate-300 hover:border-blue-500 transition disabled:opacity-50">
            🔐 Generate RSA-4096 Full (for Sign/Verify)
          </button>

          {output?.error && <div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">❌ {output.error}</div>}
          {output?.success && (
            <div className="mt-4">
              {output.rsaFull ? (
                <>
                  <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold mb-1">RSA-4096 Full Key Pair</div>
                  <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3 text-xs font-mono break-all text-slate-300 max-h-25 overflow-auto">{output.pubPem}</div>
                  <div className="mt-2 p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">✅ Full key pair ready for Sign & Verify</div>
                </>
              ) : (
                <>
                  <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold mb-1">Generated Key</div>
                  <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 text-xs font-mono break-all text-slate-300 max-h-25 overflow-auto">
                    {output.data.public_key || output.data.key_id}
                  </div>
                  <div className="mt-2 p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">✅ Generated in {output.elapsed} ms</div>
                </>
              )}
            </div>
          )}
        </div>

        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <h3 className="font-semibold mb-5 pb-3 border-b border-slate-800">🗃️ Session Key Store</h3>
          <div className="space-y-2 max-h-87.5 overflow-y-auto mb-4">
            {generated.length === 0 ? (
              <div className="text-center text-slate-600 py-8">
                <span className="text-3xl">🗝️</span>
                <p className="text-sm mt-2">No keys generated yet</p>
              </div>
            ) : generated.map((k, i) => (
              <div key={i} className="bg-slate-950 border border-slate-700 rounded-lg p-3">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold">{k.type}</span>
                  <span className="text-[0.65rem] text-blue-400 font-mono">#{i + 1}</span>
                </div>
                <div className="text-xs font-mono text-slate-400 break-all">{(k.publicKey || k.id).substring(0, 80)}{(k.publicKey || k.id).length > 80 ? '…' : ''}</div>
              </div>
            ))}
          </div>
          <button onClick={clearAll}
            className="w-full py-2.5 rounded-lg text-sm font-semibold border border-red-500/30 text-red-400 hover:bg-red-500/10 transition">
            🗑️ Clear All Keys
          </button>
        </div>
      </div>
    </div>
  );
}
