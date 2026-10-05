import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function IconShield({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconMenu({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  );
}

function IconX({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

export function BaseLayout({ sidebar }: { sidebar: React.ReactNode }) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { user, logout } = useAuth();

  return (
    <div className="min-h-screen flex" style={{ background: 'var(--color-parchment)' }}>
      {/* ── Desktop Sidebar ── */}
      <div
        className="hidden md:flex flex-col w-64 flex-shrink-0 border-r border-warm-mist"
        style={{
          background: 'linear-gradient(180deg, #f3f0eb 0%, #edeae4 100%)',
          boxShadow: 'inset -1px 0 0 rgba(0,0,0,0.02)',
        }}
      >
        {sidebar}
        <div className="mt-auto px-3 pb-4">
           {user && (
             <div className="flex flex-col gap-2">
                <span className="text-[12px] text-graphite px-3">{user.name} ({user.role})</span>
                <button
                  onClick={logout}
                  className="text-left px-3 py-2 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors"
                >
                  Sign Out
                </button>
             </div>
           )}
        </div>
      </div>

      {/* ── Mobile Drawer Overlay ── */}
      {drawerOpen && (
        <div className="md:hidden fixed inset-0 z-50">
          <div
            className="absolute inset-0 bg-ink/20 backdrop-blur-sm transition-opacity"
            onClick={() => setDrawerOpen(false)}
          />
          {/* Drawer */}
          <div
            className="absolute left-0 top-0 h-full w-64 border-r border-warm-mist shadow-subtle z-50 flex flex-col"
            style={{ background: '#f3f0eb' }}
          >
            {sidebar}
            <div className="mt-auto px-3 pb-4">
              {user && (
                 <div className="flex flex-col gap-2 border-t border-warm-mist pt-4">
                    <span className="text-[12px] text-graphite px-3">{user.name}</span>
                    <button
                      onClick={() => {
                        logout();
                        setDrawerOpen(false);
                      }}
                      className="text-left px-3 py-2 text-[13px] text-graphite hover:text-ink hover:bg-warm-mist/40 rounded-[12px] transition-colors"
                    >
                      Sign Out
                    </button>
                 </div>
               )}
            </div>
          </div>
        </div>
      )}

      {/* ── Main Content Area ── */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Mobile Header */}
        <header className="md:hidden flex items-center justify-between h-14 px-4 border-b border-warm-mist bg-[#f3f0eb]">
          <button
            onClick={() => setDrawerOpen(true)}
            className="p-1 -ml-1 text-graphite hover:text-ink transition-colors"
          >
            <IconMenu className="w-6 h-6" />
          </button>
          <div className="flex items-center gap-2">
            <IconShield className="w-5 h-5 text-ink" />
            <span className="text-[15px] font-medium text-ink">Cybor</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 px-4 sm:px-6 lg:px-10 py-8">
          <div className="max-w-[900px] mx-auto w-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
