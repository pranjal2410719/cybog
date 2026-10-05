import { Link, useLocation } from 'react-router-dom';
import { BaseLayout } from './BaseLayout';

function IconList({ className = '' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
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

function ValidatorSidebar() {
  const location = useLocation();

  const nav = [
    { to: '/validator/queue', label: 'Validation Queue', icon: <IconList className="w-5 h-5" /> },
  ];

  return (
    <aside className="flex flex-col h-full py-5 px-3 gap-1">
      <div className="px-3 mb-6 flex items-center">
        <span className="text-[16px] font-medium text-ink tracking-tight">Cybor Validator</span>
      </div>
      <p className="px-3 mb-1 text-[12px] text-graphite uppercase tracking-wide">Navigation</p>
      <nav className="flex flex-col gap-0.5">
        {nav.map((item) => (
          <NavItem key={item.to} to={item.to} label={item.label} icon={item.icon} active={location.pathname === item.to} />
        ))}
      </nav>
    </aside>
  );
}

export function ValidatorLayout() {
  return <BaseLayout sidebar={<ValidatorSidebar />} />;
}
