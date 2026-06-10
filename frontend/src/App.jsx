import { useState } from 'react';
import { Lock, Unlock, Shield, Key, Zap, BookOpen } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useHealth } from './hooks/useHealth';
import Sidebar from './components/Sidebar';
import EncryptTab from './components/EncryptTab';
import FileTab from './components/FileTab';
import SignTab from './components/SignTab';
import KeysTab from './components/KeysTab';
import BenchmarkTab from './components/BenchmarkTab';
import GuideTab from './components/GuideTab';

const TABS = [
  { id: 'encrypt', label: 'Encrypt / Decrypt', icon: Lock },
  { id: 'file', label: 'File Vault', icon: Unlock },
  { id: 'sign', label: 'Sign & Verify', icon: Shield },
  { id: 'keys', label: 'Key Workshop', icon: Key },
  { id: 'benchmark', label: 'Benchmark', icon: Zap },
  { id: 'guide', label: 'Algorithm Guide', icon: BookOpen },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('encrypt');
  const [opsCount, setOpsCount] = useState(0);
  const [keys, setKeys] = useState({ rsa: null, ecdh: null, symmetric: [] });
  const health = useHealth();

  const incOps = () => setOpsCount(c => c + 1);

  const tabComponents = {
    encrypt: <EncryptTab keys={keys} incOps={incOps} />,
    file: <FileTab incOps={incOps} />,
    sign: <SignTab keys={keys} setKeys={setKeys} incOps={incOps} />,
    keys: <KeysTab keys={keys} setKeys={setKeys} />,
    benchmark: <BenchmarkTab />,
    guide: <GuideTab />,
  };

  return (
    <div className="flex min-h-screen">
      <Sidebar
        tabs={TABS}
        activeTab={activeTab}
        onTabChange={setActiveTab}
        health={health}
        opsCount={opsCount}
        keys={keys}
      />
      <main className="flex-1 ml-64 p-8">
        {/* Hero */}
        <header className="relative overflow-hidden rounded-2xl border border-slate-800 bg-linear-to-br from-slate-900 via-slate-900 to-blue-950/30 p-10 mb-8">
          <div className="absolute top-0 right-0 w-1/2 h-full bg-[radial-gradient(circle_at_80%_50%,rgba(59,130,246,0.08),transparent_60%)]" />
          <h1 className="text-4xl font-extrabold bg-linear-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
            🔐 Next-Level CipherForgeX
          </h1>
          <p className="text-slate-500 text-sm mt-2">
            AES-256-GCM · ChaCha20-Poly1305 · RSA-4096-OAEP · X25519-ECDH · Hybrid RSA+AES · Fernet · Argon2id · Post-Quantum Ready
          </p>
          <div className="grid grid-cols-4 gap-4 mt-6">
            {[
              { val: opsCount, lbl: 'Operations' },
              { val: '8', lbl: 'Algorithms' },
              { val: health?.fips_mode ? 'ON ✅' : 'OFF', lbl: 'FIPS 140-3' },
              { val: health ? Math.round(health.uptime_seconds) + 's' : '—', lbl: 'Uptime' },
            ].map((m, i) => (
              <div key={i} className="bg-slate-800/50 backdrop-blur border border-slate-700/50 rounded-xl p-4 text-center hover:border-blue-500/50 transition-all hover:-translate-y-0.5">
                <div className="text-2xl font-bold text-blue-400">{m.val}</div>
                <div className="text-[0.7rem] uppercase tracking-wider text-slate-500 mt-1">{m.lbl}</div>
              </div>
            ))}
          </div>
        </header>

        {/* Tab Content */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
          >
            {tabComponents[activeTab]}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
