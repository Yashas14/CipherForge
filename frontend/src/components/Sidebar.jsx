import { clsx } from 'clsx';

export default function Sidebar({ tabs, activeTab, onTabChange, health, opsCount, keys }) {
  const rsaReady = !!keys.rsa;
  const ecdhReady = !!keys.ecdh;

  return (
    <aside className="fixed left-0 top-0 h-screen w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-50">
      {/* Brand */}
      <div className="flex items-center gap-3 px-5 py-6 border-b border-slate-800">
        <span className="text-3xl">🔐</span>
        <div>
          <div className="font-extrabold text-sm">CipherForageX</div>
          <div className="text-[0.65rem] text-slate-500 uppercase tracking-widest">v2.0 Enterprise</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onTabChange(id)}
            className={clsx(
              'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all',
              activeTab === id
                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            )}
          >
            <Icon size={18} />
            {label}
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-slate-800 space-y-3">
        <div className="text-[0.68rem] uppercase tracking-wider text-slate-500 font-semibold">System Status</div>
        <div className="flex justify-between text-xs text-slate-400">
          <span>API</span>
          <span className={clsx('font-semibold', health ? 'text-emerald-400' : 'text-red-400')}>
            {health ? '● Online' : '● Offline'}
          </span>
        </div>
        <div className="flex justify-between text-xs text-slate-400">
          <span>FIPS 140-3</span>
          <span className={clsx('font-semibold', health?.fips_mode ? 'text-emerald-400' : 'text-amber-400')}>
            {health?.fips_mode ? '✅ Active' : '⚠️ Inactive'}
          </span>
        </div>
        <div className="flex justify-between text-xs text-slate-400">
          <span>Operations</span>
          <span className="font-bold text-blue-400">{opsCount}</span>
        </div>
        <div className="flex justify-between text-xs text-slate-400">
          <span>RSA-4096</span>
          <span className={rsaReady ? 'text-emerald-400' : 'text-amber-400'}>{rsaReady ? '✅' : '⚠️ None'}</span>
        </div>
        <div className="flex justify-between text-xs text-slate-400">
          <span>X25519</span>
          <span className={ecdhReady ? 'text-emerald-400' : 'text-amber-400'}>{ecdhReady ? '✅' : '⚠️ None'}</span>
        </div>
      </div>
    </aside>
  );
}
