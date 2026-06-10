import { useState } from 'react';
import { apiPost, b64encode } from '../lib/api';

export default function SignTab({ keys, setKeys, incOps }) {
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState('');
  const [verifyMsg, setVerifyMsg] = useState('');
  const [verifySig, setVerifySig] = useState('');
  const [signOutput, setSignOutput] = useState(null);
  const [verifyOutput, setVerifyOutput] = useState(null);
  const [loading, setLoading] = useState(false);

  const generateKeys = async () => {
    setLoading(true);
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
      setKeys(prev => ({ ...prev, rsa: { privPem: toPem(privBuf, 'PRIVATE'), pubPem: toPem(pubBuf, 'PUBLIC') } }));
    } catch (err) { setSignOutput({ error: err.message }); }
    finally { setLoading(false); }
  };

  const sign = async () => {
    if (!message.trim()) { setSignOutput({ error: 'Enter a message' }); return; }
    if (!keys.rsa) { setSignOutput({ error: 'Generate RSA keys first' }); return; }
    setLoading(true); setSignOutput(null);
    try {
      const t0 = performance.now();
      const data = await apiPost('/keys/sign', { message: b64encode(message), algorithm: 'rsa-pss', private_key: keys.rsa.privPem });
      const elapsed = (performance.now() - t0).toFixed(1);
      incOps();
      setSignature(data.signature);
      setVerifyMsg(message);
      setVerifySig(data.signature);
      setSignOutput({ success: true, signature: data.signature, elapsed });
    } catch (err) { setSignOutput({ error: err.message }); }
    finally { setLoading(false); }
  };

  const verify = async () => {
    if (!verifyMsg.trim() || !verifySig.trim()) { setVerifyOutput({ error: 'Fill both fields' }); return; }
    if (!keys.rsa) { setVerifyOutput({ error: 'No RSA public key' }); return; }
    setLoading(true); setVerifyOutput(null);
    try {
      const t0 = performance.now();
      const data = await apiPost('/keys/verify', { message: b64encode(verifyMsg), signature: verifySig.trim(), algorithm: 'rsa-pss', public_key: keys.rsa.pubPem });
      const elapsed = (performance.now() - t0).toFixed(1);
      incOps();
      setVerifyOutput({ valid: data.valid, elapsed });
    } catch (err) { setVerifyOutput({ valid: false, error: err.message }); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <h2 className="text-xl font-bold mb-1">✍️ Digital Signatures</h2>
      <p className="text-slate-500 text-sm mb-6">RSA-4096-PSS — non-repudiation & integrity verification</p>

      {!keys.rsa ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center">
          <p className="text-slate-400 mb-4">Generate an RSA-4096 key pair to start signing</p>
          <button onClick={generateKeys} disabled={loading}
            className="px-6 py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg transition disabled:opacity-50">
            {loading ? '⏳ Generating (may take a few seconds)…' : '⚡ Generate RSA-4096 Key Pair'}
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-6">
          {/* Sign */}
          <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
            <h3 className="font-semibold mb-4 pb-3 border-b border-slate-800">✍️ Sign Message</h3>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Message</label>
            <textarea value={message} onChange={e => setMessage(e.target.value)} rows={4}
              placeholder="Type message to sign…"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm font-mono resize-y mb-4 focus:border-blue-500 outline-none transition" />
            <button onClick={sign} disabled={loading}
              className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg transition disabled:opacity-50">
              ✍️ Sign with RSA-4096-PSS
            </button>
            {signOutput?.error && <div className="mt-3 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">❌ {signOutput.error}</div>}
            {signOutput?.success && (
              <div className="mt-4">
                <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold mb-1">Signature</div>
                <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 text-xs font-mono break-all text-slate-300 max-h-25 overflow-auto">{signOutput.signature}</div>
                <div className="mt-2 p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">✅ Signed in {signOutput.elapsed} ms</div>
              </div>
            )}
          </div>

          {/* Verify */}
          <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
            <h3 className="font-semibold mb-4 pb-3 border-b border-slate-800">🔍 Verify Signature</h3>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Original Message</label>
            <textarea value={verifyMsg} onChange={e => setVerifyMsg(e.target.value)} rows={2}
              placeholder="Paste original message"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm font-mono resize-y mb-3 focus:border-blue-500 outline-none transition" />
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-400 mb-1.5">Signature (Base64)</label>
            <textarea value={verifySig} onChange={e => setVerifySig(e.target.value)} rows={2}
              placeholder="Paste Base64 signature"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm font-mono resize-y mb-4 focus:border-blue-500 outline-none transition" />
            <button onClick={verify} disabled={loading}
              className="w-full py-3 rounded-lg font-bold text-sm bg-linear-to-r from-blue-500 to-indigo-500 text-white shadow-lg transition disabled:opacity-50">
              🔍 Verify Signature
            </button>
            {verifyOutput && (
              <div className={`mt-4 p-5 rounded-xl text-center ${verifyOutput.valid ? 'bg-emerald-500/10 border border-emerald-500/40' : 'bg-red-500/10 border border-red-500/40'}`}>
                <div className="text-3xl">{verifyOutput.valid ? '✅' : '❌'}</div>
                <div className={`font-extrabold text-lg mt-1 ${verifyOutput.valid ? 'text-emerald-400' : 'text-red-400'}`}>
                  {verifyOutput.valid ? 'SIGNATURE VALID' : 'SIGNATURE INVALID'}
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  {verifyOutput.valid ? `Verified with RSA-4096-PSS · ${verifyOutput.elapsed} ms` : (verifyOutput.error || 'Signature does not match')}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
