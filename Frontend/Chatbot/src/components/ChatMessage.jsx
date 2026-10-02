import { User, Bot, Wrench, CheckCircle2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

export default function ChatMessage({ message, isDark }) {
  const isUser = message.role === 'user';

  return (
    <div
      className="animate-[slide-in_0.3s_ease-out]"
      style={{ animation: 'slide-in 0.3s ease-out' }}
    >
      <div
        className={`flex gap-4 px-6 py-5 max-w-5xl mx-auto ${
          isUser ? 'flex-row-reverse' : ''
        }`}
      >
        {/* Avatar */}
        <div
          className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
            isUser
              ? 'bg-[var(--color-accent)]'
              : isDark
              ? 'bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]'
              : 'bg-[var(--color-light-bg-tertiary)] border border-[var(--color-light-border)]'
          }`}
        >
          {isUser ? (
            <User size={20} className="text-white" />
          ) : (
            <Bot size={20} className="text-[var(--color-accent)]" />
          )}
        </div>

        {/* Message Content */}
        <div className={`flex-1 max-w-[85%] ${isUser ? 'text-right' : ''}`}>
          {/* Label */}
          <span
            className={`text-xs font-semibold mb-1.5 block uppercase tracking-wide ${
              isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
            }`}
          >
            {isUser ? 'You' : 'CTI Agent'}
          </span>

          {/* Bubble */}
          <div
            className={`inline-block text-left rounded-2xl px-5 py-4 text-[15px] leading-relaxed ${
              isUser
                ? isDark
                  ? 'bg-[var(--color-bg-user-msg)] text-[var(--color-text-primary)]'
                  : 'bg-[var(--color-light-bg-user-msg)] text-white'
                : isDark
                ? 'bg-[var(--color-bg-agent-msg)] text-[var(--color-text-primary)] border border-[var(--color-border)]'
                : 'bg-[var(--color-light-bg-agent-msg)] text-[var(--color-light-text-primary)] border border-[var(--color-light-border)]'
            }`}
          >
            {isUser ? (
              <p className="whitespace-pre-wrap">{message.content}</p>
            ) : (
              <div className="prose prose-base max-w-none prose-invert">
                <ReactMarkdown>{message.content}</ReactMarkdown>
              </div>
            )}
          </div>

          {/* Tool calls */}
          {message.toolCalls && message.toolCalls.length > 0 && (
            <div className="mt-3 space-y-2">
              {message.toolCalls.map((tool, i) => (
                <div
                  key={i}
                  className={`inline-flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-sm font-medium ${
                    tool.status === 'done'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : tool.status === 'running'
                      ? 'bg-[var(--color-accent)]/10 text-[var(--color-accent)] border border-[var(--color-accent)]/20'
                      : isDark
                      ? 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] border border-[var(--color-border)]'
                      : 'bg-[var(--color-light-bg-tertiary)] text-[var(--color-light-text-secondary)] border border-[var(--color-light-border)]'
                  }`}
                  style={
                    tool.status === 'running'
                      ? { animation: 'pulse-glow 2s ease-in-out infinite' }
                      : {}
                  }
                >
                  {tool.status === 'done' ? (
                    <CheckCircle2 size={16} />
                  ) : (
                    <Wrench size={16} />
                  )}
                  <span>{tool.name}</span>
                  {tool.status === 'running' && (
                    <span className="opacity-60">running...</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function TypingIndicator({ isDark }) {
  return (
    <div className="flex gap-4 px-6 py-5 max-w-5xl mx-auto">
      <div
        className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
          isDark
            ? 'bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]'
            : 'bg-[var(--color-light-bg-tertiary)] border border-[var(--color-light-border)]'
        }`}
      >
        <Bot size={20} className="text-[var(--color-accent)]" />
      </div>
      <div className="flex items-center gap-1.5 pt-4">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="w-2.5 h-2.5 rounded-full bg-[var(--color-accent)]"
            style={{
              animation: `typing-dot 1.4s ease-in-out ${i * 0.2}s infinite`,
            }}
          />
        ))}
      </div>
    </div>
  );
}
