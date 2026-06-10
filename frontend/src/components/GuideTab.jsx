const ALGORITHMS = [
  { name: 'AES-256-GCM', family: 'Symmetric AEAD', key: '256-bit', fips: '✅', quantum: '⚠️ Partial', use: 'General-purpose authenticated encryption (AES-NI accelerated)' },
  { name: 'ChaCha20-Poly1305', family: 'Symmetric AEAD', key: '256-bit', fips: '✅', quantum: '⚠️ Partial', use: 'Constant-time AEAD for mobile/IoT (no AES hardware needed)' },
  { name: 'RSA-4096-OAEP', family: 'Asymmetric (PKE)', key: '4096-bit modulus', fips: '✅', quantum: '❌ No', use: 'Key wrapping, small data encryption (≤446 bytes)' },
  { name: 'X25519-ECDH', family: 'Key Agreement', key: '255-bit curve', fips: '✅', quantum: '❌ No', use: 'Forward-secret ephemeral key exchange (TLS-style)' },
  { name: 'Hybrid RSA+AES', family: 'Hybrid', key: '4096+256-bit', fips: '✅', quantum: '⚠️ Partial', use: 'Large data encryption with RSA key distribution' },
  { name: 'Fernet', family: 'Symmetric', key: '256-bit', fips: '✅', quantum: '⚠️ Partial', use: 'Token encryption with built-in TTL expiry & key rotation' },
  { name: 'Argon2id + AES', family: 'Password-Based', key: '256-bit derived', fips: '✅', quantum: '⚠️ Partial', use: 'Password-protected secrets at rest (memory-hard KDF)' },
  { name: 'X25519 + Kyber-768', family: 'Post-Quantum Hybrid', key: '768-dim lattice', fips: '⏳ Pending', quantum: '✅ Quantum-Safe', use: 'Future-proof hybrid encryption (NIST PQC 2024)' },
];

export default function GuideTab() {
  return (
    <div>
      <h2 className="text-xl font-bold mb-1">📖 Algorithm Reference Guide</h2>
      <p className="text-slate-500 text-sm mb-6">Security ratings, use cases, and compliance information</p>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 mb-8">
        {ALGORITHMS.map((a, i) => (
          <div key={i} className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-5 hover:border-blue-500/50 hover:-translate-y-0.5 transition-all">
            <div className="font-bold text-sm mb-0.5">{a.name}</div>
            <div className="text-xs text-blue-400 mb-3">{a.family}</div>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
              <dt className="text-slate-500">Key Size</dt><dd className="text-slate-300">{a.key}</dd>
              <dt className="text-slate-500">FIPS 140-3</dt><dd className="text-slate-300">{a.fips}</dd>
              <dt className="text-slate-500">Quantum</dt><dd className="text-slate-300">{a.quantum}</dd>
              <dt className="text-slate-500">Use Case</dt><dd className="text-slate-300">{a.use}</dd>
            </dl>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <h3 className="font-bold text-emerald-400 mb-4">✅ Security Best Practices</h3>
          <ul className="space-y-2 text-sm text-slate-300">
            {[
              'Always use AEAD (AES-GCM, ChaCha20-Poly1305) — authentication + encryption',
              'Never reuse nonces — collision destroys GCM security entirely',
              'Use RSA-OAEP, never PKCS#1 v1.5 — Bleichenbacher padding oracle',
              'Argon2id for passwords — memory-hard, GPU/ASIC resistant',
              'Rotate keys regularly via Fernet or HKDF key hierarchy',
              'Use Hybrid mode for data > 446 bytes with asymmetric keys',
            ].map((item, i) => (
              <li key={i} className="flex gap-2 items-start">
                <span className="text-emerald-400 font-bold mt-0.5">✓</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="bg-slate-900/60 backdrop-blur border border-slate-800 rounded-xl p-6">
          <h3 className="font-bold text-red-400 mb-4">❌ Common Mistakes</h3>
          <ul className="space-y-2 text-sm text-slate-300">
            {[
              'Never use ECB mode — deterministic, leaks patterns (penguin attack)',
              'Never use MD5/SHA-1 for integrity — cryptographically broken',
              'Never hardcode keys in source code or config files',
              "Don't use DES/3DES — deprecated by NIST, vulnerable",
              "Don't use RSA < 2048 bits — use 3072+ (preferably 4096)",
              "Don't ignore authentication tags — malleable without MAC",
            ].map((item, i) => (
              <li key={i} className="flex gap-2 items-start">
                <span className="text-red-400 font-bold mt-0.5">✗</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="text-center text-slate-600 text-xs mt-8">
        CipherForageX v2.0 · NIST SP 800-175B · FIPS 140-3 · Python cryptography library · OWASP-compliant
      </div>
    </div>
  );
}
