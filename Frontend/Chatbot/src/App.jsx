import { useState, useEffect, useRef, useCallback } from 'react'
import { Plus, MessageSquare, Send, Activity, ShieldAlert, CheckCircle2, ChevronRight, TerminalSquare, Trash2, Square, Clock, Pause, Play, X, AlertTriangle } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import './App.css'

const API_BASE = 'http://localhost:8000/api'

// Node display names for each tool
const TOOL_NODE_MAP = {
  scan_natural_language_query: [
    { key: 'query_gen', label: 'Query Generation' },
    { key: 'get_ips', label: 'IP Discovery' },
    { key: 'process_all_ips', label: 'Shodan + Nmap Scanning' },
    { key: 'extract_cves', label: 'CVE Extraction' },
    { key: 'cve_mapper', label: 'NVD + ChatGPT Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
  scan_ip_list: [
    { key: 'init_ips', label: 'Initialize IPs' },
    { key: 'process_all_ips', label: 'Shodan + Nmap Scanning' },
    { key: 'extract_cves', label: 'CVE Extraction' },
    { key: 'cve_mapper', label: 'NVD + ChatGPT Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
  scan_cve_list: [
    { key: 'init_cves', label: 'Initialize CVEs' },
    { key: 'cve_mapper', label: 'NVD + ChatGPT Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
}

const ENGINE_DISPLAY_NAMES = {
  scan_natural_language_query: 'Query Engine',
  scan_ip_list: 'IP Scanner Engine',
  scan_cve_list: 'CVE Research Engine',
}

export default function App() {
  const [sessions, setSessions] = useState([])
  const [activeThreadId, setActiveThreadId] = useState(null)
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)

  // Tool approval state
  const [pendingApproval, setPendingApproval] = useState(null)  // {tool, engine_name, query, message}

  // Engine tracking state
  const [activeEngine, setActiveEngine] = useState(null)  // {engine_thread_id, engine_name, tool, nodes}
  const engineEventSourceRef = useRef(null)

  // Resume dialog state
  const [resumeDialog, setResumeDialog] = useState(null)  // {engines: [...paused engines]}

  const messagesEndRef = useRef(null)

  // Auto-scroll to bottom of chat
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }
  useEffect(() => {
    scrollToBottom()
  }, [messages, activeEngine])

  // Load chat sessions on mount
  useEffect(() => {
    fetchSessions()
  }, [])

  // Cleanup engine SSE on unmount
  useEffect(() => {
    return () => {
      if (engineEventSourceRef.current) {
        engineEventSourceRef.current.close()
      }
    }
  }, [])

  const fetchSessions = async () => {
    try {
      const res = await fetch(`${API_BASE}/chats`)
      const data = await res.json()
      setSessions(data)
    } catch (err) {
      console.error("Failed to fetch sessions", err)
    }
  }

  const handleNewChat = async () => {
    // Disconnect from any running engine SSE
    disconnectEngineStream()
    setPendingApproval(null)
    setResumeDialog(null)
    setActiveEngine(null)

    try {
      const res = await fetch(`${API_BASE}/chats/new`, { method: 'POST' })
      const data = await res.json()
      setActiveThreadId(data.thread_id)
      setMessages([])
      setSessions(prev => [{ thread_id: data.thread_id }, ...prev.filter(s => s.thread_id !== data.thread_id)])
    } catch (err) {
      console.error("Failed to create chat", err)
    }
  }

  const loadChat = async (threadId) => {
    // Disconnect from any running engine SSE
    disconnectEngineStream()
    setPendingApproval(null)
    setResumeDialog(null)
    setActiveEngine(null)

    setActiveThreadId(threadId)
    try {
      const res = await fetch(`${API_BASE}/chats/${threadId}`)
      const data = await res.json()
      
      const rawMessages = data.messages || data
      const toolCalls = data.tool_calls || []
      
      // Build a map of message_index -> tool_calls
      const toolsByMsgIdx = {}
      toolCalls.forEach(tc => {
        const idx = tc.message_index
        if (idx !== null && idx !== undefined) {
          if (!toolsByMsgIdx[idx]) toolsByMsgIdx[idx] = []
          toolsByMsgIdx[idx].push({
            name: tc.tool_name,
            input: tc.input_data,
            status: tc.status === 'paused' ? 'paused' : tc.status === 'done' ? 'done' : tc.status === 'error' ? 'done' : 'done',
            output: tc.result_summary,
            engine_id: tc.engine_thread_id,
            tool_call_id: tc.tool_call_id,
            nodes: tc.progress || {},
          })
        }
      })
      
      const mergedMessages = rawMessages.map(msg => {
        const tools = toolsByMsgIdx[msg.message_index] || []
        if (msg.role === 'assistant' && tools.length > 0) {
          return { ...msg, tools }
        }
        return msg
      })
      
      setMessages(mergedMessages)

      // Check for running or paused engines
      await checkEngineStatus(threadId)

    } catch (err) {
      console.error("Failed to load chat", err)
    }
  }

  const checkEngineStatus = async (threadId) => {
    try {
      const res = await fetch(`${API_BASE}/chats/${threadId}/engines`)
      const data = await res.json()

      // If there's a pending tool approval (agent is waiting for human decision),
      // show the approval card — even after server restart
      if (data.pending_approval) {
        setPendingApproval(data.pending_approval)
        return
      }

      // If an engine is currently running, connect to its SSE stream
      if (data.has_running && data.running_engine_thread_id) {
        const runningEngine = data.engines.find(e => e.engine_thread_id === data.running_engine_thread_id)
        if (runningEngine) {
          connectToEngineStream(
            data.running_engine_thread_id,
            ENGINE_DISPLAY_NAMES[runningEngine.tool_name] || runningEngine.tool_name,
            runningEngine.tool_name,
            runningEngine.progress || {}
          )
        }
        return
      }

      // If there are paused/incomplete engines, show resume dialog
      const pausedEngines = data.engines.filter(e => e.status === 'paused')
      if (pausedEngines.length > 0) {
        setResumeDialog({ engines: pausedEngines })
      }
    } catch (err) {
      console.error("Failed to check engine status", err)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Engine SSE Stream
  // ─────────────────────────────────────────────────────────────────────────

  const connectToEngineStream = useCallback((engineThreadId, engineName, toolName, initialNodes = {}) => {
    // Disconnect existing
    disconnectEngineStream()

    const toolNodeList = TOOL_NODE_MAP[toolName] || []
    const nodeStates = {}
    toolNodeList.forEach(n => {
      nodeStates[n.key] = initialNodes[n.key] || { status: 'pending', detail: '' }
    })

    setActiveEngine({
      engine_thread_id: engineThreadId,
      engine_name: engineName,
      tool: toolName,
      nodes: nodeStates,
      status: 'running',
    })

    // Connect to SSE
    const evtSource = new EventSource(`${API_BASE}/engine/${engineThreadId}/stream`)
    engineEventSourceRef.current = evtSource

    const handleProgressEvent = (data) => {
      setActiveEngine(prev => {
        if (!prev) return prev
        const nodes = { ...prev.nodes }

        nodes[data.node] = { status: data.status, detail: data.detail || '' }

        // Mark previous nodes as done
        const nodeDefList = TOOL_NODE_MAP[prev.tool] || []
        const currentIdx = nodeDefList.findIndex(n => n.key === data.node)
        if (currentIdx >= 0) {
          for (let i = 0; i < currentIdx; i++) {
            const key = nodeDefList[i].key
            if (nodes[key] && nodes[key].status === 'pending') {
              nodes[key] = { status: 'done', detail: nodes[key].detail || '' }
            }
          }
        }

        return { ...prev, nodes }
      })
    }

    const handleDoneEvent = () => {
      setActiveEngine(prev => {
        if (!prev) return prev
        const nodes = { ...prev.nodes }
        Object.keys(nodes).forEach(key => {
          nodes[key] = { ...nodes[key], status: 'done' }
        })
        return { ...prev, nodes, status: 'done' }
      })
      evtSource.close()
      engineEventSourceRef.current = null
    }

    const handlePausedEvent = () => {
      setActiveEngine(prev => {
        if (!prev) return prev
        const nodes = { ...prev.nodes }
        Object.keys(nodes).forEach(key => {
          if (nodes[key].status === 'running') {
            nodes[key] = { ...nodes[key], status: 'paused' }
          }
        })
        return { ...prev, nodes, status: 'paused' }
      })
      evtSource.close()
      engineEventSourceRef.current = null
    }

    const handleErrorEvent = (data) => {
      setActiveEngine(prev => prev ? { ...prev, status: 'error', error: data.error || 'Unknown error' } : prev)
      evtSource.close()
      engineEventSourceRef.current = null
    }

    // Named event listeners (for sse_starlette which sends event: type)
    evtSource.addEventListener('engine_progress', (e) => {
      try { handleProgressEvent(JSON.parse(e.data)) } catch {}
    })
    evtSource.addEventListener('engine_done', (e) => handleDoneEvent())
    evtSource.addEventListener('engine_paused', (e) => handlePausedEvent())
    evtSource.addEventListener('engine_error', (e) => {
      try { handleErrorEvent(JSON.parse(e.data)) } catch {}
    })

    // Fallback: generic onmessage handler (catches events without explicit event: field)
    evtSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'engine_progress') handleProgressEvent(data)
        else if (data.type === 'engine_done') handleDoneEvent()
        else if (data.type === 'engine_paused') handlePausedEvent()
        else if (data.type === 'engine_error') handleErrorEvent(data)
      } catch {}
    }

    evtSource.onerror = () => {
      // Don't close immediately on error — EventSource auto-reconnects
      // Only close if the engine is done/paused
      setTimeout(() => {
        setActiveEngine(prev => {
          if (prev && prev.status === 'running') {
            // Still running — let EventSource reconnect
            return prev
          }
          return prev
        })
      }, 2000)
    }
  }, [])

  const disconnectEngineStream = () => {
    if (engineEventSourceRef.current) {
      engineEventSourceRef.current.close()
      engineEventSourceRef.current = null
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Chat Deletion
  // ─────────────────────────────────────────────────────────────────────────

  const handleDeleteChat = async (threadId, e) => {
    e.stopPropagation()
    // Stop any running engine for this chat first
    try {
      const enginesRes = await fetch(`${API_BASE}/chats/${threadId}/engines`)
      const enginesData = await enginesRes.json()
      if (enginesData.has_running && enginesData.running_engine_thread_id) {
        await fetch(`${API_BASE}/engine/${enginesData.running_engine_thread_id}/stop`, { method: 'POST' })
      }
    } catch {}

    try {
      await fetch(`${API_BASE}/chats/${threadId}`, { method: 'DELETE' })
      if (activeThreadId === threadId) {
        disconnectEngineStream()
        setActiveThreadId(null)
        setMessages([])
        setActiveEngine(null)
        setPendingApproval(null)
        setResumeDialog(null)
      }
      fetchSessions()
    } catch (err) {
      console.error("Failed to delete chat", err)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Agent Stop
  // ─────────────────────────────────────────────────────────────────────────

  const handleStopAgent = async () => {
    if (!activeThreadId || !isStreaming) return
    try {
      await fetch(`${API_BASE}/chats/${activeThreadId}/stop`, { method: 'POST' })
      setIsStreaming(false)
    } catch (err) {
      console.error("Failed to stop agent", err)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Engine Stop
  // ─────────────────────────────────────────────────────────────────────────

  const handleStopEngine = async () => {
    if (!activeEngine || (activeEngine.status !== 'running' && activeEngine.status !== 'pausing')) return
    setActiveEngine(prev => prev ? { ...prev, status: 'pausing' } : prev)
    try {
      await fetch(`${API_BASE}/engine/${activeEngine.engine_thread_id}/stop`, { method: 'POST' })
    } catch (err) {
      console.error("Failed to stop engine", err)
      setActiveEngine(prev => prev ? { ...prev, status: 'running' } : prev)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Tool Approval
  // ─────────────────────────────────────────────────────────────────────────

  const handleApproval = async (action) => {
    if (!activeThreadId || !pendingApproval) return
    setPendingApproval(null)

    setMessages(prev => [...prev, { role: 'assistant', content: '', tools: [] }])
    setIsStreaming(true)

    try {
      const response = await fetch(`${API_BASE}/chats/${activeThreadId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      })

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const blocks = buffer.split(/\r?\n\r?\n/)
        buffer = blocks.pop() || ''

        for (const block of blocks) {
          if (!block.trim()) continue
          const lines = block.split(/\r?\n/)
          const dataLine = lines.find(l => l.startsWith('data: '))
          if (dataLine) {
            try {
              const event = JSON.parse(dataLine.replace('data: ', ''))
              handleStreamEvent(event)
            } catch {}
          }
        }
      }
    } catch (err) {
      console.error("Approval stream error", err)
    } finally {
      setIsStreaming(false)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Resume Dialog & Manual Resume
  // ─────────────────────────────────────────────────────────────────────────

  const handleResumeEngine = async (engine) => {
    setResumeDialog(null)

    const toolName = engine.tool_name || engine.tool
    const displayName = ENGINE_DISPLAY_NAMES[toolName] || engine.engine_name || toolName

    try {
      const res = await fetch(`${API_BASE}/engine/${engine.engine_thread_id}/resume`, { method: 'POST' })
      const data = await res.json()

      if (data.status === 'resumed') {
        connectToEngineStream(
          engine.engine_thread_id,
          displayName,
          toolName,
          engine.progress || engine.nodes || {}
        )
      }
    } catch (err) {
      console.error("Failed to resume engine", err)
    }
  }

  const dismissResumeDialog = () => {
    setResumeDialog(null)
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Send Message + Stream Handler
  // ─────────────────────────────────────────────────────────────────────────

  const sendMessage = async () => {
    if (!input.trim()) return

    // Don't allow sending if an engine is running
    if (activeEngine && activeEngine.status === 'running') {
      return
    }

    const userMsg = input.trim()
    setInput('')
    
    let currentThreadId = activeThreadId
    
    if (!currentThreadId) {
      try {
        const res = await fetch(`${API_BASE}/chats/new`, { method: 'POST' })
        const data = await res.json()
        currentThreadId = data.thread_id
        setActiveThreadId(currentThreadId)
        setSessions(prev => [{ thread_id: currentThreadId }, ...prev.filter(s => s.thread_id !== currentThreadId)])
      } catch (err) {
        console.error("Failed to create auto-chat", err)
        return
      }
    }
    
    setMessages(prev => [...prev, { role: 'user', content: userMsg }])
    setMessages(prev => [...prev, { role: 'assistant', content: '', tools: [] }])
    setIsStreaming(true)

    try {
      const response = await fetch(`${API_BASE}/chats/${currentThreadId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg })
      })

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        
        buffer += decoder.decode(value, { stream: true })
        const blocks = buffer.split(/\r?\n\r?\n/)
        buffer = blocks.pop() || ''

        for (const block of blocks) {
          if (!block.trim()) continue
          const lines = block.split(/\r?\n/)
          const dataLine = lines.find(l => l.startsWith('data: '))
          if (dataLine) {
            const dataStr = dataLine.replace('data: ', '')
            try {
              const event = JSON.parse(dataStr)
              handleStreamEvent(event)
            } catch (e) {
              // Ignore parse errors for incomplete chunks
            }
          }
        }
      }
    } catch (err) {
      console.error("Stream error", err)
    } finally {
      setIsStreaming(false)
    }
  }

  const handleStreamEvent = (event) => {
    if (event.type === 'tool_approval') {
      // Agent wants to run a tool — show approval dialog
      setPendingApproval({
        tool: event.tool,
        engine_name: event.engine_name,
        query: event.query,
        message: event.message,
      })
      setIsStreaming(false)
      return
    }

    if (event.type === 'engine_started') {
      // Engine just started in the background — connect to its SSE stream
      connectToEngineStream(
        event.engine_thread_id,
        event.engine_name,
        event.tool,
      )
      return
    }

    setMessages(prevMessages => {
      if (prevMessages.length === 0) return prevMessages
      
      const newMessages = [...prevMessages]
      const lastMsg = { ...newMessages[newMessages.length - 1] }
      newMessages[newMessages.length - 1] = lastMsg
      
      if (lastMsg.role !== 'assistant') return prevMessages

      if (event.type === 'token') {
        lastMsg.content = (lastMsg.content || '') + event.content
      } 
      else if (event.type === 'tool_start') {
        // Don't show tool block for engine tools — they'll show via the approval card
        // and engine progress panel instead
        const engineTools = ['scan_natural_language_query', 'scan_ip_list', 'scan_cve_list']
        if (engineTools.includes(event.tool)) {
          return newMessages  // Skip — engine panel will handle display
        }

        const toolNodes = TOOL_NODE_MAP[event.tool] || []
        const nodeStates = {}
        toolNodes.forEach(n => {
          nodeStates[n.key] = { status: 'pending', detail: '' }
        })
        
        lastMsg.tools = [...(lastMsg.tools || []), {
          name: event.tool,
          input: event.input,
          status: 'running',
          output: null,
          engine_id: event.engine_id || null,
          nodes: nodeStates,
        }]
      }
      else if (event.type === 'tool_end') {
        if (lastMsg.tools && lastMsg.tools.length > 0) {
          const toolsCopy = [...lastMsg.tools]
          const activeTool = { ...toolsCopy[toolsCopy.length - 1] }
          activeTool.status = 'done'
          activeTool.output = event.output
          toolsCopy[toolsCopy.length - 1] = activeTool
          lastMsg.tools = toolsCopy
        }
      }
      else if (event.type === 'stopped') {
        lastMsg.content = (lastMsg.content || '') + '\n\n*Agent stopped by user.*'
      }
      
      return newMessages
    })
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  const isEngineRunning = activeEngine && (activeEngine.status === 'running' || activeEngine.status === 'pausing')

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="brand-icon">
            <ShieldAlert size={20} color="white" />
          </div>
          <span className="brand-name">CTI Agent</span>
        </div>

        <button className="new-chat-btn" onClick={handleNewChat}>
          <Plus size={16} /> New Investigation
        </button>

        <span className="history-label">History</span>
        <div className="chat-history-list">
          {sessions.map(session => (
            <div 
              key={session.thread_id} 
              className={`history-item ${activeThreadId === session.thread_id ? 'active' : ''}`}
              onClick={() => loadChat(session.thread_id)}
            >
              <div className="history-item-content">
                <MessageSquare size={16} />
                <span className="history-item-text">{session.thread_id}</span>
              </div>
              <button 
                className="delete-chat-btn" 
                onClick={(e) => handleDeleteChat(session.thread_id, e)}
                title="Delete Chat"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      </aside>

      {/* Main Chat Area */}
      <main className="main-content">
        {!activeThreadId ? (
          <div className="welcome-screen">
            <ShieldAlert size={48} className="welcome-icon" />
            <h1 className="welcome-title">Welcome to <span>CTI Agent</span></h1>
            <p className="welcome-subtitle">
              Your AI-powered Cyber Threat Intelligence analyst. Ask me to scan IPs, lookup CVEs, or discover vulnerabilities.
            </p>
          </div>
        ) : (
          <div className="chat-area">
            {/* Resume Dialog */}
            {resumeDialog && (
              <ResumeDialog 
                engines={resumeDialog.engines} 
                onResume={handleResumeEngine}
                onDismiss={dismissResumeDialog}
              />
            )}

            {messages.map((msg, idx) => (
              <div key={idx} className={`message-wrapper ${msg.role}`}>
                <div className="message-content">
                  <div className={`avatar ${msg.role}`}>
                    {msg.role === 'user' ? 'U' : <ShieldAlert size={18} color="white" />}
                  </div>
                  <div className="message-body">
                    {/* Render tool executions before the text response */}
                    {msg.role === 'assistant' && msg.tools && msg.tools.map((tool, tIdx) => (
                      <ToolExecutionBlock key={tIdx} tool={tool} />
                    ))}
                    
                    {/* Render markdown text with GFM plugin for tables */}
                    {msg.content && (
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.content}</ReactMarkdown>
                    )}
                    
                    {/* Blink cursor if streaming */}
                    {isStreaming && idx === messages.length - 1 && !msg.content && (!msg.tools || msg.tools.length === 0) && (
                      <span style={{opacity: 0.5}}>...</span>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {/* Tool Approval Dialog */}
            {pendingApproval && (
              <ToolApprovalCard 
                approval={pendingApproval} 
                onAccept={() => handleApproval('accept')}
                onDecline={() => handleApproval('decline')}
              />
            )}

            {/* Live Engine Progress Panel */}
            {activeEngine && (
              <EngineProgressPanel 
                engine={activeEngine} 
                onStop={handleStopEngine}
                onResume={handleResumeEngine}
              />
            )}

            <div ref={messagesEndRef} />
          </div>
        )}

        {/* Input Area */}
        <div className="input-area">
          <div className="input-container">
            <input 
              type="text" 
              className="chat-input" 
              placeholder={isEngineRunning ? "Engine is running... wait for it to finish" : "Ask CTI Agent to scan an IP or CVE..."}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
              disabled={isStreaming || isEngineRunning || !!pendingApproval}
            />
            {isStreaming ? (
              <button 
                className="stop-btn" 
                onClick={handleStopAgent}
                title="Stop Agent"
              >
                <Square size={16} fill="currentColor" />
              </button>
            ) : (
              <button 
                className="send-btn" 
                onClick={sendMessage}
                disabled={!input.trim() || isEngineRunning || !!pendingApproval}
              >
                <Send size={16} />
              </button>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}


/**
 * Tool Approval Card — shown when agent wants to run an engine tool
 */
function ToolApprovalCard({ approval, onAccept, onDecline }) {
  return (
    <div className="message-wrapper assistant">
      <div className="message-content">
        <div className="avatar assistant">
          <ShieldAlert size={18} color="white" />
        </div>
        <div className="message-body">
          <div className="approval-card">
            <div className="approval-header">
              <TerminalSquare size={18} />
              <span>Agent wants to run a tool</span>
            </div>
            <div className="approval-body">
              <div className="approval-engine-name">{approval.engine_name}</div>
              <div className="approval-query">"{approval.query}"</div>
            </div>
            <div className="approval-actions">
              <button className="approval-accept" onClick={onAccept}>
                <CheckCircle2 size={16} /> Accept
              </button>
              <button className="approval-decline" onClick={onDecline}>
                <X size={16} /> Decline
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}


/**
 * Live Engine Progress Panel — shown while engine runs in background
 */
function EngineProgressPanel({ engine, onStop, onResume }) {
  const predefinedNodes = TOOL_NODE_MAP[engine.tool] || []
  const allNodeKeys = new Set(predefinedNodes.map(n => n.key))
  const dynamicNodes = Object.keys(engine.nodes || {})
    .filter(key => !allNodeKeys.has(key))
    .map(key => ({ key, label: key.startsWith('nmap_') ? key.replace('nmap_', 'Nmap: ').replace(/_/g, '.') : key }))
  
  const nodeList = [...predefinedNodes, ...dynamicNodes]
  const isDone = engine.status === 'done'
  const isPaused = engine.status === 'paused'
  const isPausing = engine.status === 'pausing'
  const isError = engine.status === 'error'

  return (
    <div className={`engine-panel ${engine.status}`}>
      <div className="engine-panel-header">
        <div className="engine-panel-title">
          <TerminalSquare size={16} />
          <span>{engine.engine_name}</span>
        </div>
        <div className="engine-panel-controls">
          {engine.status === 'running' && (
            <button className="engine-stop-btn" onClick={onStop} title="Pause Engine">
              <Pause size={14} /> Stop
            </button>
          )}
          {engine.status === 'pausing' && (
            <button className="engine-stop-btn disabled" disabled title="Stopping Engine...">
              <Activity size={14} className="spin" /> Stopping...
            </button>
          )}
          {engine.status === 'paused' && onResume && (
            <button className="engine-resume-btn" onClick={() => onResume(engine)} title="Resume Engine">
              <Play size={14} /> Resume
            </button>
          )}
          <div className={`engine-status-badge ${engine.status}`}>
            {engine.status === 'running' && <><Activity size={12} /> Running</>}
            {engine.status === 'pausing' && <><Activity size={12} className="spin" /> Stopping...</>}
            {engine.status === 'done' && <><CheckCircle2 size={12} /> Complete</>}
            {engine.status === 'paused' && <><Pause size={12} /> Paused</>}
            {engine.status === 'error' && <><AlertTriangle size={12} /> Error</>}
          </div>
        </div>
      </div>

      <div className="engine-panel-nodes">
        {nodeList.map((nodeDef, index) => {
          const nodeState = engine.nodes?.[nodeDef.key] || { status: 'pending', detail: '' }
          let displayStatus = nodeState.status
          if (isDone) displayStatus = 'done'
          if (isPaused && displayStatus === 'running') displayStatus = 'paused'

          return (
            <div key={index} className={`node-item ${displayStatus}`}>
              <div className="node-indicator">
                {displayStatus === 'done' && <CheckCircle2 size={12} />}
                {displayStatus === 'running' && <Activity size={12} className="spin" />}
                {displayStatus === 'paused' && <Pause size={12} />}
                {displayStatus === 'pending' && <Clock size={12} />}
              </div>
              <span className="node-name">{nodeDef.label}</span>
              {nodeState.detail && (
                <span className="node-detail">{nodeState.detail}</span>
              )}
            </div>
          )
        })}
      </div>

      {isError && engine.error && (
        <div className="engine-error-msg">{engine.error}</div>
      )}
    </div>
  )
}


/**
 * Resume Dialog — shown when user opens a chat with paused engines
 */
function ResumeDialog({ engines, onResume, onDismiss }) {
  return (
    <div className="resume-dialog">
      <div className="resume-dialog-header">
        <AlertTriangle size={18} />
        <span>You have incomplete engine runs</span>
      </div>
      <div className="resume-dialog-body">
        {engines.map((engine, idx) => {
          const displayName = ENGINE_DISPLAY_NAMES[engine.tool_name] || engine.tool_name
          const queryText = engine.input_data?.query || engine.input_data?.ip_addresses?.join(', ') || engine.input_data?.cve_ids?.join(', ') || 'Unknown'

          return (
            <div key={idx} className="resume-engine-item" onClick={() => onResume(engine)}>
              <div className="resume-engine-info">
                <span className="resume-engine-name">{displayName}</span>
                <span className="resume-engine-query">"{queryText}"</span>
              </div>
              <div className="resume-engine-status">
                <Pause size={12} /> Paused
              </div>
              <button className="resume-engine-btn">
                <Play size={14} /> Resume
              </button>
            </div>
          )
        })}
      </div>
      <div className="resume-dialog-footer">
        <button className="resume-dismiss-btn" onClick={onDismiss}>
          Continue without resuming
        </button>
      </div>
    </div>
  )
}


/**
 * Renders a stylized block showing the engine pipeline with real-time node progress.
 * (Used for historical tool calls loaded from DB)
 */
function ToolExecutionBlock({ tool }) {
  const predefinedNodes = TOOL_NODE_MAP[tool.name] || [
    { key: 'processing', label: 'Processing' },
  ]
  const allNodeKeys = new Set(predefinedNodes.map(n => n.key))
  const dynamicNodes = Object.keys(tool.nodes || {})
    .filter(key => !allNodeKeys.has(key) && key !== 'processing')
    .map(key => ({ key, label: key.startsWith('nmap_') ? key.replace('nmap_', 'Nmap: ').replace(/_/g, '.') : key }))
  
  const nodeList = [...predefinedNodes, ...dynamicNodes]

  const isDone = tool.status === 'done'
  const isPaused = tool.status === 'paused'

  return (
    <div className={`tool-block ${tool.status}`}>
      <div className="tool-header">
        <div className="tool-title">
          <TerminalSquare size={16} />
          {ENGINE_DISPLAY_NAMES[tool.name] || tool.name}
        </div>
        <div className={`tool-status-badge ${tool.status}`}>
          {tool.status === 'running' ? (
            <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
              <Activity size={12} /> Running Engine
            </span>
          ) : tool.status === 'paused' ? (
            <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
              <Pause size={12} /> Paused
            </span>
          ) : (
            <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
              <CheckCircle2 size={12} /> Completed
            </span>
          )}
        </div>
      </div>
      
      <div className="tool-nodes">
        {nodeList.map((nodeDef, index) => {
          const nodeState = tool.nodes?.[nodeDef.key] || { status: 'pending', detail: '' }
          
          let displayStatus = nodeState.status
          if (isDone) displayStatus = 'done'

          return (
            <div key={index} className={`node-item ${displayStatus}`}>
              <div className="node-indicator">
                {displayStatus === 'done' && <CheckCircle2 size={12} />}
                {displayStatus === 'running' && <Activity size={12} className="spin" />}
                {displayStatus === 'paused' && <Pause size={12} />}
                {displayStatus === 'pending' && <Clock size={12} />}
              </div>
              <span className="node-name">{nodeDef.label}</span>
              {nodeState.detail && (
                <span className="node-detail">{nodeState.detail}</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
