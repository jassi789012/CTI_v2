import { Wifi, WifiOff, Server, ServerOff } from 'lucide-react';

export default function StatusIndicator({ isDark, backendStatus }) {
  const isOnline = navigator.onLine;
  const isBackendOk = backendStatus === 'healthy';

  return (
    <div className="flex items-center gap-4">
      {/* Network Status */}
      <div className="flex items-center gap-2" title={isOnline ? 'Network connected' : 'Network disconnected'}>
        {isOnline ? (
          <Wifi size={16} className="text-[var(--color-success)]" />
        ) : (
          <WifiOff size={16} className="text-[var(--color-error)]" />
        )}
        <span
          className={`text-sm ${
            isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
          }`}
        >
          {isOnline ? 'Online' : 'Offline'}
        </span>
      </div>

      {/* Divider */}
      <div
        className={`w-px h-4 ${isDark ? 'bg-[var(--color-border-light)]' : 'bg-[var(--color-light-border)]'}`}
      />

      {/* Backend Status */}
      <div className="flex items-center gap-2" title={isBackendOk ? 'Backend connected' : 'Backend disconnected'}>
        {isBackendOk ? (
          <Server size={16} className="text-[var(--color-success)]" />
        ) : (
          <ServerOff size={16} className="text-[var(--color-error)]" />
        )}
        <span
          className={`text-sm ${
            isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
          }`}
        >
          {isBackendOk ? 'Backend' : 'No Backend'}
        </span>
      </div>
    </div>
  );
}
