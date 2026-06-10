import { useState } from 'react';
import { apiPost, formatBytes } from '../lib/api';

export default function FileTab({ incOps }) {
  const [mode, setMode] = useState('encrypt');
  const [algo, setAlgo] = useState('aes-gcm');
  const [file, setFile] = useState(null);
  const [decKey, setDecKey] = useState('');
  const [output, setOutput] = useState(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const handleFile = (f) => { setFile(f); setOutput(null); };

  const run = async () => {
    if (!file) { setOutput({ error: 'Upload a file first' }); return; }
    setLoading(true); setOutput(null);

    try {
      const buffer = await file.arrayBuffer();
      const b64 = btoa(new Uint8Array(buffer).reduce((d, b) => d + String.fromCharCode(b), ''));
      const t0 = performance.now();

      if (mode === 'encrypt') {
        const data = await apiPost('/encrypt/text', { plaintext: b64, algorithm: algo });
        const elapsed = (performance.now() - t0).toFixed(1);
        incOps();
        setOutput({ success: true, encrypted: true, data: data.ciphertext, key: data.metadata?.key, elapsed, name: file.name + '.enc' });
      } else {
        if (!decKey.trim()) { setOutput({ error: 'Enter the decryption key' }); setLoading(false); return; }
        const data = await apiPost('/decrypt/text', { ciphertext: b64, algorithm: algo, key_id: decKey.trim() });
        const elapsed = (performance.now() - t0).toFixed(1);
        incOps();
        setOutput({ success: true, encrypted: false, data: data.plaintext, elapsed, name: file.name.replace(/\.enc$/, '') });
      }
    } catch (err) { setOutput({ error: err.message }); }
    finally { setLoading(false); }
  };

  const download = () => {
    if (!output?.data) return;
    const binary = atob(output.data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = output.name;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">📁 File Vault</h2>
      <p className="text-slate-500 text-sm mb-6">Encrypt and decrypt files with authenticated encryption</p>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-5 pb-3 border-b border-slate-800">
            <h3 className="font-semibold">Upload</h3>
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
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-4 focus:border-blue-500 outline-none transition">
            <option value="aes-gcm">AES-256-GCM</option>
            <option value="chacha20">ChaCha20-Poly1305</option>
          </select>

          {/* Dropzone */}
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { e.preventDefault(); setDragOver(false); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); }}
            onClick={() => document.getElementById('file-input-hidden').click()}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition mb-4 ${dragOver ? 'border-blue-500 bg-blue-500/5' : 'border-slate-700 hover:border-slate-500'}`}>
            <div className="text-3xl mb-2">📄</div>
            <p className="text-sm text-slate-400">{file ? file.name : 'Drag & Drop or click to browse'}</p>
            {file && <span className="text-xs text-slate-500">{formatBytes(file.size)}</span>}
            <input id="file-input-hidden" type="file" hidden onChange={e => { if (e.target.files[0]) handleFile(e.target.files[0]); }} />
          </div>

          {mode === 'decrypt' && (
            <>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Decryption Key (Base64)</label>
              <input type="password" value={decKey} onChange={e => setDecKey(e.target.value)} placeholder="Paste the key"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm mb-4 focus:border-blue-500 outline-none transition" />
            </>
          )}

          <button onClick={run} disabled={loading}
            className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg shadow-blue-500/20 transition disabled:opacity-50">
            {loading ? '⏳ Processing…' : '⚡ Process File'}
          </button>
        </div>

        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <h3 className="font-semibold mb-5 pb-3 border-b border-slate-800">Result</h3>
          <div className="bg-slate-950 border border-slate-700 rounded-lg p-4 min-h-62.5">
            {!output && <div className="flex flex-col items-center justify-center h-full text-slate-600 py-12"><span className="text-4xl mb-2">📁</span><p className="text-sm">Upload a file to get started</p></div>}
            {output?.error && <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">❌ {output.error}</div>}
            {output?.success && (
              <>
                {output.key && (
                  <>
                    <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold mb-1">🔑 Decryption Key</div>
                    <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mb-3 text-amber-300 text-xs font-mono break-all">{output.key}</div>
                  </>
                )}
                <button onClick={download}
                  className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-emerald-500 to-teal-500 text-white mb-3">
                  ⬇️ Download {output.encrypted ? 'Encrypted' : 'Decrypted'} File
                </button>
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm font-semibold">
                  ✅ {output.encrypted ? 'Encrypted' : 'Decrypted'} in {output.elapsed} ms
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
