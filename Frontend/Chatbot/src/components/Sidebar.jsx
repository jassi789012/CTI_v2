import { useState } from 'react';
import { Plus, MessageSquare, Trash2, Sun, Moon, ChevronLeft, ChevronRight } from 'lucide-react';

export default function Sidebar({
  chats,
  activeChat,
  onSelectChat,
  onNewChat,
  onDeleteChat,
  isDark,
  onToggleTheme,
  isCollapsed,
  onToggleCollapse,
}) {
  const [hoveredChat, setHoveredChat] = useState(null);

  if (isCollapsed) {
    return (
      <div
        className={`flex flex-col items-center py-5 gap-5 w-16 shrink-0 border-r transition-colors duration-300 ${
          isDark
            ? 'bg-[var(--color-bg-sidebar)] border-[var(--color-border)]'
            : 'bg-[var(--color-light-bg-sidebar)] border-[var(--color-light-border)]'
        }`}
      >
        <button
          onClick={onToggleCollapse}
          className={`p-2.5 rounded-lg transition-colors ${
            isDark ? 'hover:bg-[var(--color-bg-hover)] text-[var(--color-text-secondary)]' : 'hover:bg-[var(--color-light-bg-hover)] text-[var(--color-light-text-secondary)]'
          }`}
          title="Expand sidebar"
        >
          <ChevronRight size={20} />
        </button>
        <button
          onClick={onNewChat}
          className="p-2.5 rounded-lg bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-colors"
          title="New chat"
        >
          <Plus size={20} />
        </button>
      </div>
    );
  }

  return (
    <div
      className={`flex flex-col w-80 shrink-0 border-r transition-colors duration-300 ${
        isDark
          ? 'bg-[var(--color-bg-sidebar)] border-[var(--color-border)]'
          : 'bg-[var(--color-light-bg-sidebar)] border-[var(--color-light-border)]'
      }`}
    >
      {/* Header */}
      <div
        className={`flex items-center justify-between px-5 py-5 border-b ${
          isDark ? 'border-[var(--color-border)]' : 'border-[var(--color-light-border)]'
        }`}
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--color-accent)] flex items-center justify-center">
            <span className="text-white font-bold text-base">C</span>
          </div>
          <h1
            className={`font-semibold text-base ${
              isDark ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-light-text-primary)]'
            }`}
          >
            CTI Agent
          </h1>
        </div>
        <button
          onClick={onToggleCollapse}
          className={`p-2 rounded-lg transition-colors ${
            isDark ? 'hover:bg-[var(--color-bg-hover)] text-[var(--color-text-muted)]' : 'hover:bg-[var(--color-light-bg-hover)] text-[var(--color-light-text-muted)]'
          }`}
        >
          <ChevronLeft size={18} />
        </button>
      </div>

      {/* New Chat Button */}
      <div className="px-4 py-4">
        <button
          onClick={onNewChat}
          className="w-full flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] transition-all duration-200 text-base font-medium"
        >
          <Plus size={18} />
          New Chat
        </button>
      </div>

      {/* Chat List */}
      <div className="flex-1 overflow-y-auto px-3 pb-3">
        {chats.length === 0 && (
          <p
            className={`text-sm text-center mt-10 ${
              isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
            }`}
          >
            No conversations yet
          </p>
        )}

        {chats.map((chat) => (
          <div
            key={chat.thread_id}
            onMouseEnter={() => setHoveredChat(chat.thread_id)}
            onMouseLeave={() => setHoveredChat(null)}
            onClick={() => onSelectChat(chat.thread_id)}
            className={`group flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all duration-150 mb-1 ${
              activeChat === chat.thread_id
                ? isDark
                  ? 'bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]'
                  : 'bg-[var(--color-light-bg-tertiary)] text-[var(--color-light-text-primary)]'
                : isDark
                ? 'text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]'
                : 'text-[var(--color-light-text-secondary)] hover:bg-[var(--color-light-bg-hover)]'
            }`}
          >
            <MessageSquare size={16} className="shrink-0 opacity-60" />
            <span className="flex-1 text-sm truncate">
              {chat.title || chat.thread_id}
            </span>
            {hoveredChat === chat.thread_id && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDeleteChat(chat.thread_id);
                }}
                className={`p-1.5 rounded-lg transition-colors ${
                  isDark ? 'hover:bg-[var(--color-error)]/20 text-[var(--color-error)]' : 'hover:bg-red-100 text-red-500'
                }`}
              >
                <Trash2 size={15} />
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Footer — Theme Toggle */}
      <div
        className={`px-4 py-4 border-t ${
          isDark ? 'border-[var(--color-border)]' : 'border-[var(--color-light-border)]'
        }`}
      >
        <button
          onClick={onToggleTheme}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-colors text-sm ${
            isDark
              ? 'text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]'
              : 'text-[var(--color-light-text-secondary)] hover:bg-[var(--color-light-bg-hover)]'
          }`}
        >
          {isDark ? <Sun size={18} /> : <Moon size={18} />}
          {isDark ? 'Light Mode' : 'Dark Mode'}
        </button>
      </div>
    </div>
  );
}
