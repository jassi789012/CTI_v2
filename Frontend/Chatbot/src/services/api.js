/**
 * CTI API Service
 * Handles all communication with the FastAPI backend.
 */

const API_BASE = '/api';

// ═══════════════════════════════════════════════════════════════════════════
// Chat Management
// ═══════════════════════════════════════════════════════════════════════════

export async function createNewChat() {
  const res = await fetch(`${API_BASE}/chats/new`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to create chat');
  return res.json(); // { thread_id: "chat_abc123" }
}

export async function listChats() {
  const res = await fetch(`${API_BASE}/chats`);
  if (!res.ok) throw new Error('Failed to list chats');
  return res.json(); // [{ thread_id: "chat_abc123" }, ...]
}

export async function getChatHistory(threadId) {
  const res = await fetch(`${API_BASE}/chats/${threadId}`);
  if (!res.ok) throw new Error('Failed to get chat history');
  return res.json(); // [{ role: "user", content: "..." }, ...]
}

export async function deleteChat(threadId) {
  const res = await fetch(`${API_BASE}/chats/${threadId}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete chat');
  return res.json();
}

// ═══════════════════════════════════════════════════════════════════════════
// Agent Streaming (SSE)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send a message to the agent and stream back events.
 * 
 * @param {string} threadId - The chat session ID
 * @param {string} message - The user's message
 * @param {object} callbacks - Event callbacks:
 *   onToken(text)        — Called for each text chunk from the agent
 *   onToolStart(name, input) — Called when a tool starts executing
 *   onToolEnd(name, output)  — Called when a tool finishes
 *   onDone(threadId)     — Called when streaming is complete
 *   onError(message)     — Called on error
 * @returns {AbortController} - Call .abort() to cancel the stream
 */
export function streamMessage(threadId, message, callbacks) {
  const controller = new AbortController();

  fetch(`${API_BASE}/chats/${threadId}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
    signal: controller.signal,
  })
    .then(async (response) => {
      if (!response.ok) {
        const err = await response.text();
        callbacks.onError?.(err);
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const event = JSON.parse(line.slice(6));

              switch (event.type) {
                case 'token':
                  callbacks.onToken?.(event.content);
                  break;
                case 'tool_start':
                  callbacks.onToolStart?.(event.tool, event.input);
                  break;
                case 'tool_end':
                  callbacks.onToolEnd?.(event.tool, event.output);
                  break;
                case 'done':
                  callbacks.onDone?.(event.thread_id);
                  break;
                case 'error':
                  callbacks.onError?.(event.message);
                  break;
                case 'stopped':
                  callbacks.onDone?.(threadId);
                  break;
              }
            } catch {
              // Skip malformed lines
            }
          }
        }
      }

      callbacks.onDone?.(threadId);
    })
    .catch((err) => {
      if (err.name !== 'AbortError') {
        callbacks.onError?.(err.message);
      }
    });

  return controller;
}

export async function stopAgent(threadId) {
  const res = await fetch(`${API_BASE}/chats/${threadId}/stop`, { method: 'POST' });
  return res.json();
}

// ═══════════════════════════════════════════════════════════════════════════
// Health Check
// ═══════════════════════════════════════════════════════════════════════════

export async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return { status: 'error', database: 'disconnected' };
    return res.json();
  } catch {
    return { status: 'error', database: 'disconnected' };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Stats
// ═══════════════════════════════════════════════════════════════════════════

export async function getStats() {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to get stats');
  return res.json();
}
