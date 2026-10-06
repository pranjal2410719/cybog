import { Link, useLocation } from 'react-router-dom';
import { BaseLayout } from './BaseLayout';

function IconGrid({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
    </svg>
  );
}

function IconPlus({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 5v14M5 12h14" />
    </svg>
  );
}

function NavItem({ to, icon, label, active }: { to: string; icon: React.ReactNode; label: string; active?: boolean }) {
  return (
    <Link
      to={to}
      className={`flex items-center gap-3 px-3 py-2 rounded-[12px] text-[13px] font-medium transition-colors ${
        active
          ? 'bg-ink text-white shadow-sm'
          : 'text-graphite hover:text-ink hover:bg-warm-mist/40'
      }`}
    >
      <span className="w-5 h-5 flex-shrink-0">{icon}</span>
      <span>{label}</span>
    </Link>
  );
}

function OperatorSidebar() {
  const location = useLocation();

  const nav = [
    { to: '/operator/dashboard', label: 'Dashboard', icon: <IconGrid className="w-5 h-5" /> },
    { to: '/operator/assessments/new', label: 'New Assessment', icon: <IconPlus className="w-5 h-5" /> },
  ];

  return (
    <aside className="flex flex-col h-full py-5 px-3 gap-1">
      <div className="px-3 mb-6 flex items-center">
        <span className="text-[16px] font-medium text-ink tracking-tight">Cybor Operator</span>
      </div>
      <p className="px-3 mb-1 text-[12px] text-graphite uppercase tracking-wide">Navigation</p>
      <nav className="flex flex-col gap-0.5">
        {nav.map((item) => (
          <NavItem key={item.to} to={item.to} label={item.label} icon={item.icon} active={location.pathname.startsWith(item.to)} />
        ))}
      </nav>
    </aside>
  );
}

export function OperatorLayout() {
  return <BaseLayout sidebar={<OperatorSidebar />} />;
}
