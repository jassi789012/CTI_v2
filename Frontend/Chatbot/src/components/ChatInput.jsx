import { useState, useRef, useEffect } from 'react';
import { Send, Square } from 'lucide-react';

export default function ChatInput({ onSend, onStop, isStreaming, isDark, disabled }) {
  const [message, setMessage] = useState('');
  const textareaRef = useRef(null);

  // Auto-resize textarea
  useEffect(() => {
    const ta = textareaRef.current;
    if (ta) {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 200) + 'px';
    }
  }, [message]);

  const handleSend = () => {
    const trimmed = message.trim();
    if (!trimmed || isStreaming || disabled) return;
    onSend(trimmed);
    setMessage('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div
      className={`border-t px-6 py-4 ${
        isDark ? 'border-[var(--color-border)]' : 'border-[var(--color-light-border)]'
      }`}
    >
      <div className="max-w-5xl mx-auto">
        <div
          className={`flex items-end gap-3 rounded-2xl px-5 py-4 transition-colors border ${
            isDark
              ? 'bg-[var(--color-bg-input)] border-[var(--color-border)] focus-within:border-[var(--color-accent)]'
              : 'bg-[var(--color-light-bg-input)] border-[var(--color-light-border)] focus-within:border-[var(--color-accent)]'
          }`}
        >
          <textarea
            ref={textareaRef}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={disabled ? 'Backend not connected...' : 'Message CTI Agent...'}
            disabled={disabled || isStreaming}
            rows={1}
            className={`flex-1 resize-none bg-transparent outline-none text-base leading-relaxed max-h-[200px] ${
              isDark
                ? 'text-[var(--color-text-primary)] placeholder:text-[var(--color-text-muted)]'
                : 'text-[var(--color-light-text-primary)] placeholder:text-[var(--color-light-text-muted)]'
            }`}
          />

          {isStreaming ? (
            <button
              onClick={onStop}
              className="p-3 rounded-xl bg-[var(--color-error)] text-white hover:opacity-90 transition-opacity shrink-0"
              title="Stop generating"
            >
              <Square size={18} fill="currentColor" />
            </button>
          ) : (
            <button
              onClick={handleSend}
              disabled={!message.trim() || disabled}
              className={`p-3 rounded-xl transition-all shrink-0 ${
                message.trim() && !disabled
                  ? 'bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)]'
                  : isDark
                  ? 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-muted)] cursor-not-allowed'
                  : 'bg-[var(--color-light-bg-tertiary)] text-[var(--color-light-text-muted)] cursor-not-allowed'
              }`}
              title="Send message"
            >
              <Send size={18} />
            </button>
          )}
        </div>

        <p
          className={`text-xs text-center mt-2.5 ${
            isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
          }`}
        >
          CTI Agent can make mistakes. Verify scan results independently.
        </p>
      </div>
    </div>
  );
}
