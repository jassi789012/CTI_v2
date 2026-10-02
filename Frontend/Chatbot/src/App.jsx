import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield } from 'lucide-react';
import Sidebar from './components/Sidebar';
import ChatMessage, { TypingIndicator } from './components/ChatMessage';
import ChatInput from './components/ChatInput';
import StatusIndicator from './components/StatusIndicator';
import { createNewChat, listChats, getChatHistory, deleteChat, streamMessage, stopAgent, checkHealth } from './services/api';

export default function App() {
  // ─── State ──────────────────────────────────────────────────────────────
  const [isDark, setIsDark] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [chats, setChats] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [backendStatus, setBackendStatus] = useState('checking');
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  const messagesEndRef = useRef(null);
  const abortRef = useRef(null);

  // ─── Auto-scroll ────────────────────────────────────────────────────────
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // ─── Network status listener ────────────────────────────────────────────
  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  // ─── Backend health check (every 15s) ───────────────────────────────────
  useEffect(() => {
    const check = async () => {
      const health = await checkHealth();
      setBackendStatus(health.status);
    };
    check();
    const interval = setInterval(check, 15000);
    return () => clearInterval(interval);
  }, []);

  // ─── Load chat list on mount ────────────────────────────────────────────
  useEffect(() => {
    loadChats();
  }, []);

  const loadChats = async () => {
    try {
      const sessions = await listChats();
      setChats(sessions.map((s) => ({ thread_id: s.thread_id, title: s.thread_id })));
    } catch {
      // Backend not available yet
    }
  };

  // ─── Select a chat ─────────────────────────────────────────────────────
  const handleSelectChat = async (threadId) => {
    setActiveChat(threadId);
    try {
      const history = await getChatHistory(threadId);
      setMessages(history);
    } catch {
      setMessages([]);
    }
  };

  // ─── New chat ──────────────────────────────────────────────────────────
  const handleNewChat = async () => {
    try {
      const { thread_id } = await createNewChat();
      const newChat = { thread_id, title: thread_id };
      setChats((prev) => [newChat, ...prev]);
      setActiveChat(thread_id);
      setMessages([]);
    } catch {
      const fallbackId = `chat_${Date.now().toString(36)}`;
      const newChat = { thread_id: fallbackId, title: fallbackId };
      setChats((prev) => [newChat, ...prev]);
      setActiveChat(fallbackId);
      setMessages([]);
    }
  };

  // ─── Delete chat ───────────────────────────────────────────────────────
  const handleDeleteChat = async (threadId) => {
    try {
      await deleteChat(threadId);
    } catch {
      // Delete locally even if backend fails
    }
    setChats((prev) => prev.filter((c) => c.thread_id !== threadId));
    if (activeChat === threadId) {
      setActiveChat(null);
      setMessages([]);
    }
  };

  // ─── Send message ─────────────────────────────────────────────────────
  const handleSend = async (text) => {
    // Auto-create a new chat if none is active
    let threadId = activeChat;
    if (!threadId) {
      try {
        const { thread_id } = await createNewChat();
        const newChat = { thread_id, title: text.slice(0, 40) + (text.length > 40 ? '...' : '') };
        setChats((prev) => [newChat, ...prev]);
        setActiveChat(thread_id);
        threadId = thread_id;
      } catch {
        const fallbackId = `chat_${Date.now().toString(36)}`;
        const newChat = { thread_id: fallbackId, title: text.slice(0, 40) };
        setChats((prev) => [newChat, ...prev]);
        setActiveChat(fallbackId);
        threadId = fallbackId;
      }
    }

    // Add user message
    const userMsg = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);

    // Update chat title to first user message
    setChats((prev) =>
      prev.map((c) =>
        c.thread_id === threadId && c.title === threadId
          ? { ...c, title: text.slice(0, 40) + (text.length > 40 ? '...' : '') }
          : c
      )
    );

    // Start streaming
    setIsStreaming(true);
    setMessages((prev) => [...prev, { role: 'assistant', content: '', toolCalls: [] }]);

    const controller = streamMessage(threadId, text, {
      onToken: (content) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = { ...last, content: last.content + content };
          }
          return updated;
        });
      },

      onToolStart: (name) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            const toolCalls = [...(last.toolCalls || []), { name, status: 'running' }];
            updated[updated.length - 1] = { ...last, toolCalls };
          }
          return updated;
        });
      },

      onToolEnd: (name) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            const toolCalls = (last.toolCalls || []).map((tc) =>
              tc.name === name && tc.status === 'running' ? { ...tc, status: 'done' } : tc
            );
            updated[updated.length - 1] = { ...last, toolCalls };
          }
          return updated;
        });
      },

      onDone: () => {
        setIsStreaming(false);
      },

      onError: (errMsg) => {
        setMessages((prev) => {
          const updated = [...prev];
          const last = updated[updated.length - 1];
          if (last && last.role === 'assistant') {
            updated[updated.length - 1] = {
              ...last,
              content: last.content || `⚠️ Error: ${errMsg}`,
            };
          }
          return updated;
        });
        setIsStreaming(false);
      },
    });

    abortRef.current = controller;
  };

  // ─── Stop agent ────────────────────────────────────────────────────────
  const handleStop = async () => {
    if (abortRef.current) abortRef.current.abort();
    if (activeChat) {
      try { await stopAgent(activeChat); } catch { /* ignore */ }
    }
    setIsStreaming(false);
  };

  // ─── Render ────────────────────────────────────────────────────────────
  const bgClass = isDark ? 'bg-[var(--color-bg-primary)]' : 'bg-[var(--color-light-bg-primary)]';

  return (
    <div className={`flex h-full w-full ${bgClass} transition-colors duration-300`}>
      {/* Sidebar */}
      <Sidebar
        chats={chats}
        activeChat={activeChat}
        onSelectChat={handleSelectChat}
        onNewChat={handleNewChat}
        onDeleteChat={handleDeleteChat}
        isDark={isDark}
        onToggleTheme={() => setIsDark((d) => !d)}
        isCollapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
      />

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <div
          className={`flex items-center justify-between px-6 py-4 border-b shrink-0 ${
            isDark ? 'border-[var(--color-border)]' : 'border-[var(--color-light-border)]'
          }`}
        >
          <div className="flex items-center gap-3">
            <Shield size={22} className="text-[var(--color-accent)]" />
            <span
              className={`text-base font-semibold ${
                isDark ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-light-text-primary)]'
              }`}
            >
              {activeChat
                ? chats.find((c) => c.thread_id === activeChat)?.title || 'Chat'
                : 'CTI Agent'}
            </span>
          </div>
          <StatusIndicator isDark={isDark} backendStatus={backendStatus} />
        </div>

        {/* Messages Area */}
        <div
          className={`flex-1 overflow-y-auto ${
            isDark ? 'bg-[var(--color-bg-chat)]' : 'bg-[var(--color-light-bg-chat)]'
          }`}
        >
          {!activeChat && messages.length === 0 ? (
            /* ── Welcome Screen ── */
            <div className="flex flex-col items-center justify-center h-full px-6">
              <div
                className="w-20 h-20 rounded-2xl bg-[var(--color-accent)] flex items-center justify-center mb-8"
                style={{ animation: 'fade-in 0.5s ease-out' }}
              >
                <Shield size={40} className="text-white" />
              </div>
              <h2
                className={`text-3xl font-bold mb-3 ${
                  isDark ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-light-text-primary)]'
                }`}
              >
                CTI Agent
              </h2>
              <p
                className={`text-base text-center max-w-lg mb-10 leading-relaxed ${
                  isDark ? 'text-[var(--color-text-secondary)]' : 'text-[var(--color-light-text-secondary)]'
                }`}
              >
                Your AI-powered Cyber Threat Intelligence analyst. Scan IPs, discover vulnerabilities,
                and map CVEs to MITRE ATT&CK techniques.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-3xl w-full">
                {[
                  { label: '🔍 Scan IPs', example: '"Scan 1.2.3.4 for vulnerabilities"' },
                  { label: '🌐 Find Targets', example: '"Find Apache servers in Germany"' },
                  { label: '🛡️ Research CVEs', example: '"Analyze CVE-2024-1234"' },
                ].map((item) => (
                  <button
                    key={item.label}
                    onClick={handleNewChat}
                    className={`text-left px-5 py-5 rounded-2xl border transition-all duration-200 hover:scale-[1.02] ${
                      isDark
                        ? 'bg-[var(--color-bg-tertiary)] border-[var(--color-border)] hover:border-[var(--color-accent)] text-[var(--color-text-primary)]'
                        : 'bg-[var(--color-light-bg-tertiary)] border-[var(--color-light-border)] hover:border-[var(--color-accent)] text-[var(--color-light-text-primary)]'
                    }`}
                  >
                    <span className="text-sm font-semibold">{item.label}</span>
                    <p
                      className={`text-sm mt-2 leading-relaxed ${
                        isDark ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-light-text-muted)]'
                      }`}
                    >
                      {item.example}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            /* ── Chat Messages ── */
            <div className="py-4">
              {messages.map((msg, i) => (
                <ChatMessage key={i} message={msg} isDark={isDark} />
              ))}
              {isStreaming && messages[messages.length - 1]?.content === '' && (
                <TypingIndicator isDark={isDark} />
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Input Area */}
        <ChatInput
          onSend={handleSend}
          onStop={handleStop}
          isStreaming={isStreaming}
          isDark={isDark}
          disabled={backendStatus !== 'healthy'}
        />
      </div>
    </div>
  );
}
