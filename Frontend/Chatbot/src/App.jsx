import { useState, useEffect, useRef, useCallback } from 'react'
import { Plus, MessageSquare, Send, Activity, ShieldAlert, CheckCircle2, ChevronRight, TerminalSquare, Trash2, Square, Clock, Pause, Play, X, AlertTriangle, Search, Database } from 'lucide-react'
import { Link } from 'react-router-dom'
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
    { key: 'cve_mapper', label: 'OSINT CVE Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
  scan_ip_list: [
    { key: 'init_ips', label: 'Initialize IPs' },
    { key: 'process_all_ips', label: 'Shodan + Nmap Scanning' },
    { key: 'extract_cves', label: 'CVE Extraction' },
    { key: 'cve_mapper', label: 'OSINT CVE Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
  scan_cve_list: [
    { key: 'init_cves', label: 'Initialize CVEs' },
    { key: 'cve_mapper', label: 'OSINT CVE Enrichment' },
    { key: 'summary', label: 'Summary' },
  ],
}

const ENGINE_DISPLAY_NAMES = {
  scan_natural_language_query: 'Query Engine',
  scan_ip_list: 'IP Scanner Engine',
  scan_cve_list: 'CVE Research Engine',
}

// Display names for lightweight tool indicators (non-engine tools)
const TOOL_DISPLAY_NAMES = {
  query_database: { running: 'Querying database', done: 'Queried database' },
  sql_db_schema: { running: 'Reading table schema', done: 'Read table schema' },
  sql_db_list_tables: { running: 'Listing tables', done: 'Listed tables' },
}

// Engine tools that use the full ToolExecutionBlock with pipeline nodes
const ENGINE_TOOL_NAMES = ['scan_natural_language_query', 'scan_ip_list', 'scan_cve_list']

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
  const streamAbortControllerRef = useRef(null)

  // Engines sidebar state
  const [enginesList, setEnginesList] = useState([])
  const [isRightPanelOpen, setIsRightPanelOpen] = useState(true)
  const activeEngineRef = useRef(activeEngine)
  useEffect(() => { activeEngineRef.current = activeEngine }, [activeEngine])

  // Conflict alert dialog state
  const [engineConflictAlert, setEngineConflictAlert] = useState(null)

  // Helper: check if any engine is currently running in this chat
  const getRunningEngine = () => {
    if (activeEngine && (activeEngine.status === 'running' || activeEngine.status === 'pausing')) {
      return activeEngine
    }
    const fromList = enginesList.find(e => e.status === 'running' || e.status === 'pausing')
    if (fromList) return fromList
    for (const msg of messages) {
      if (msg.tools) {
        const t = msg.tools.find(tool => tool.status === 'running' || tool.status === 'pausing')
        if (t) return t
      }
    }
    return null
  }

  const messagesEndRef = useRef(null)
  const chatAreaRef = useRef(null)
  const isNearBottomRef = useRef(true)

  const handleChatScroll = () => {
    if (!chatAreaRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = chatAreaRef.current
    // User is near bottom if within 150px of the bottom
    isNearBottomRef.current = scrollHeight - scrollTop - clientHeight < 150
  }

  // Auto-scroll to bottom of chat only if user is already near bottom or forced
  const scrollToBottom = (force = false) => {
    if (force || isNearBottomRef.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }

  useEffect(() => {
    scrollToBottom(false)
  }, [messages])

  // Load chat sessions on mount and set title
  useEffect(() => {
    fetchSessions()
  }, [])

  useEffect(() => {
    document.title = activeThreadId ? `${activeThreadId} | CTI Agent` : 'CTI Agent — Threat Intelligence'
  }, [activeThreadId])

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
    // Abort any active response stream & engine SSE
    if (streamAbortControllerRef.current) {
      streamAbortControllerRef.current.abort()
      streamAbortControllerRef.current = null
    }
    setIsStreaming(false)
    disconnectEngineStream()
    setPendingApproval(null)
    setActiveEngine(null)
    setEnginesList([])
    isNearBottomRef.current = true

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
    // Abort any active response stream & engine SSE
    if (streamAbortControllerRef.current) {
      streamAbortControllerRef.current.abort()
      streamAbortControllerRef.current = null
    }
    setIsStreaming(false)
    disconnectEngineStream()
    setPendingApproval(null)
    setActiveEngine(null)
    isNearBottomRef.current = true

    setActiveThreadId(threadId)
    try {
      const [chatRes, enginesRes] = await Promise.all([
        fetch(`${API_BASE}/chats/${threadId}`),
        fetch(`${API_BASE}/chats/${threadId}/engines`),
      ])
      const data = await chatRes.json()
      const enginesData = await enginesRes.json()
      
      const rawMessages = data.messages || data
      const toolCalls = data.tool_calls || []

      // Build a map of message_index -> tool_calls
      const toolsByMsgIdx = {}
      toolCalls.forEach(tc => {
        let idx = tc.message_index
        if (idx === null || idx === undefined) {
          // Fallback: match assistant message by engine_thread_id in content or default to first assistant
          const matchIdx = rawMessages.findIndex(m => m.role === 'assistant' && m.content && tc.engine_thread_id && m.content.includes(tc.engine_thread_id))
          if (matchIdx !== -1) {
            idx = rawMessages[matchIdx].message_index
          } else {
            const firstAsst = rawMessages.find(m => m.role === 'assistant')
            idx = firstAsst ? firstAsst.message_index : 0
          }
        }

        if (idx !== null && idx !== undefined) {
          if (!toolsByMsgIdx[idx]) toolsByMsgIdx[idx] = []
          toolsByMsgIdx[idx].push({
            name: tc.tool_name,
            tool_name: tc.tool_name,
            input: tc.input_data,
            input_data: tc.input_data,
            status: tc.status || 'done',
            output: tc.result_summary,
            engine_id: tc.engine_thread_id,
            engine_thread_id: tc.engine_thread_id,
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
      setEnginesList(enginesData?.engines || [])

      // Apply engine status (approval card or live stream)
      applyEngineStatus(enginesData)

    } catch (err) {
      console.error("Failed to load chat", err)
    }
  }

  const applyEngineStatus = (data) => {
    if (!data) return

    // If there's a pending tool approval (agent is waiting for human decision),
    // show the approval card — even after server restart
    if (data.pending_approval) {
      setPendingApproval(data.pending_approval)
      return
    }

    // If an engine is currently running, connect to its SSE stream
    if (data.has_running && data.running_engine_thread_id) {
      const runningEngine = data.engines?.find(e => e.engine_thread_id === data.running_engine_thread_id)
      if (runningEngine) {
        connectToEngineStream(
          data.running_engine_thread_id,
          ENGINE_DISPLAY_NAMES[runningEngine.tool_name] || runningEngine.tool_name,
          runningEngine.tool_name,
          runningEngine.progress || {}
        )
      }
    }
  }

  const checkEngineStatus = async (threadId) => {
    try {
      const res = await fetch(`${API_BASE}/chats/${threadId}/engines`)
      const data = await res.json()
      applyEngineStatus(data)
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
    Object.keys(initialNodes || {}).forEach(k => {
      if (!nodeStates[k]) {
        nodeStates[k] = initialNodes[k]
      }
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
      setEnginesList(prev => prev.map(e => 
        ((e.engine_thread_id || e.engine_id) === engineThreadId) ? { ...e, status: 'done' } : e
      ))
      setMessages(prev => prev.map(msg => {
        if (!msg.tools) return msg
        return {
          ...msg,
          tools: msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
              const updatedNodes = { ...(t.nodes || {}) }
              Object.keys(updatedNodes).forEach(k => {
                updatedNodes[k] = { ...updatedNodes[k], status: 'done' }
              })
              return { ...t, status: 'done', nodes: updatedNodes }
            }
            return t
          })
        }
      }))
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
      setEnginesList(prev => prev.map(e => 
        ((e.engine_thread_id || e.engine_id) === engineThreadId) ? { ...e, status: 'paused' } : e
      ))
      setMessages(prev => prev.map(msg => {
        if (!msg.tools) return msg
        return {
          ...msg,
          tools: msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
              const updatedNodes = { ...(t.nodes || {}) }
              Object.keys(updatedNodes).forEach(k => {
                if (updatedNodes[k].status === 'running') {
                  updatedNodes[k] = { ...updatedNodes[k], status: 'paused' }
                }
              })
              return { ...t, status: 'paused', nodes: updatedNodes }
            }
            return t
          })
        }
      }))
      evtSource.close()
      engineEventSourceRef.current = null
    }

    const handleErrorEvent = (data) => {
      setActiveEngine(prev => prev ? { ...prev, status: 'error', error: data.error || 'Unknown error' } : prev)
      setEnginesList(prev => prev.map(e => 
        ((e.engine_thread_id || e.engine_id) === engineThreadId) ? { ...e, status: 'error' } : e
      ))
      setMessages(prev => prev.map(msg => {
        if (!msg.tools) return msg
        return {
          ...msg,
          tools: msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
              return { ...t, status: 'error', error: data.error || 'Unknown error' }
            }
            return t
          })
        }
      }))
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

    if (!window.confirm(`Are you sure you want to delete investigation "${threadId}"? This will terminate any running operations for this chat.`)) {
      return
    }

    const isCurrentActive = activeThreadId === threadId

    // 1. Immediately tear down local stream & states if deleting current active chat
    if (isCurrentActive) {
      if (streamAbortControllerRef.current) {
        streamAbortControllerRef.current.abort()
        streamAbortControllerRef.current = null
      }
      disconnectEngineStream()
      setIsStreaming(false)
      setActiveEngine(null)
      setActiveThreadId(null)
      setMessages([])
      setPendingApproval(null)
      setEnginesList([])
    }

    // 2. Optimistically remove from sidebar
    setSessions(prev => prev.filter(s => s.thread_id !== threadId))

    // 3. Proactively signal stop to backend agent & running engines
    try {
      fetch(`${API_BASE}/chats/${threadId}/stop`, { method: 'POST' }).catch(() => {})
      
      const enginesRes = await fetch(`${API_BASE}/chats/${threadId}/engines`)
      if (enginesRes.ok) {
        const enginesData = await enginesRes.json()
        if (enginesData.has_running && enginesData.running_engine_thread_id) {
          fetch(`${API_BASE}/engine/${enginesData.running_engine_thread_id}/stop`, { method: 'POST' }).catch(() => {})
        }
      }
    } catch {}

    // 4. Send DELETE request (backend stops all engines, cancels events, and cleans checkpoints)
    try {
      await fetch(`${API_BASE}/chats/${threadId}`, { method: 'DELETE' })
    } catch (err) {
      console.error("Failed to delete chat", err)
    } finally {
      fetchSessions()
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Agent Stop
  // ─────────────────────────────────────────────────────────────────────────

  const handleStopAgent = async () => {
    if (streamAbortControllerRef.current) {
      streamAbortControllerRef.current.abort()
      streamAbortControllerRef.current = null
    }
    if (!activeThreadId || !isStreaming) return
    try {
      await fetch(`${API_BASE}/chats/${activeThreadId}/stop`, { method: 'POST' })
    } catch (err) {
      console.error("Failed to stop agent", err)
    } finally {
      setIsStreaming(false)
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Engine Stop
  // ─────────────────────────────────────────────────────────────────────────

  const handleStopEngine = async (targetEngine = null) => {
    const engineObj = (targetEngine && (targetEngine.engine_thread_id || targetEngine.engine_id))
      ? targetEngine
      : activeEngine
    const engineThreadId = engineObj?.engine_thread_id || engineObj?.engine_id
    if (!engineThreadId) return

    if (activeEngine && (activeEngine.engine_thread_id === engineThreadId)) {
      setActiveEngine(prev => prev ? { ...prev, status: 'pausing' } : prev)
    }
    setEnginesList(prev => prev.map(e => 
      ((e.engine_thread_id || e.engine_id) === engineThreadId)
        ? { ...e, status: 'pausing' }
        : e
    ))
    setMessages(prev => prev.map(msg => {
      if (!msg.tools) return msg
      return {
        ...msg,
        tools: msg.tools.map(t => {
          if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
            return { ...t, status: 'pausing' }
          }
          return t
        })
      }
    }))

    try {
      await fetch(`${API_BASE}/engine/${engineThreadId}/stop`, { method: 'POST' })
    } catch (err) {
      console.error("Failed to stop engine", err)
      if (activeEngine && (activeEngine.engine_thread_id === engineThreadId)) {
        setActiveEngine(prev => prev ? { ...prev, status: 'running' } : prev)
      }
      setEnginesList(prev => prev.map(e => 
        ((e.engine_thread_id || e.engine_id) === engineThreadId)
          ? { ...e, status: 'running' }
          : e
      ))
      setMessages(prev => prev.map(msg => {
        if (!msg.tools) return msg
        return {
          ...msg,
          tools: msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
              return { ...t, status: 'running' }
            }
            return t
          })
        }
      }))
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Tool Approval
  // ─────────────────────────────────────────────────────────────────────────

  const handleApproval = async (action) => {
    if (!activeThreadId || !pendingApproval) return

    if (action === 'accept') {
      const running = getRunningEngine()
      if (running) {
        setEngineConflictAlert("Already one engine is running in this chat. Pause it first to run a second engine.")
        return
      }
    }

    setPendingApproval(null)

    setMessages(prev => [...prev, { role: 'assistant', content: '', tools: [] }])
    setIsStreaming(true)

    if (streamAbortControllerRef.current) {
      streamAbortControllerRef.current.abort()
    }
    const controller = new AbortController()
    streamAbortControllerRef.current = controller

    try {
      const response = await fetch(`${API_BASE}/chats/${activeThreadId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
        signal: controller.signal
      })

      if (!response.ok) {
        let errData = null
        try { errData = await response.json() } catch {}
        setEngineConflictAlert(errData?.detail || "Already one engine is running in this chat. Pause it first to run a second engine.")
        setMessages(prev => prev.slice(0, prev.length - 1))
        return
      }

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
      if (err.name === 'AbortError') return
      console.error("Approval stream error", err)
      setMessages(prev => {
        if (prev.length === 0) return prev
        const copy = [...prev]
        const last = { ...copy[copy.length - 1] }
        if (last.role === 'assistant' && !last.content) {
          last.content = `⚠️ **Connection Error:** Could not stream approval decision (${err.message || 'Network error'}).`
          copy[copy.length - 1] = last
        }
        return copy
      })
    } finally {
      setIsStreaming(false)
      if (streamAbortControllerRef.current === controller) {
        streamAbortControllerRef.current = null
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Resume Dialog & Manual Resume
  // ─────────────────────────────────────────────────────────────────────────

  const handleResumeEngine = async (engine) => {
    const engineThreadId = engine.engine_thread_id || engine.engine_id
    if (!engineThreadId) {
      console.error("Cannot resume engine: missing engine thread ID", engine)
      return
    }

    const running = getRunningEngine()
    if (running && (running.engine_thread_id || running.engine_id) !== engineThreadId) {
      setEngineConflictAlert("Already one engine is running in this chat. Pause it first before resuming another engine.")
      return
    }

    const toolName = engine.tool_name || engine.tool || engine.name
    const displayName = ENGINE_DISPLAY_NAMES[toolName] || engine.engine_name || toolName

    // Optimistically mark this engine as running in messages so the UI updates immediately in place
    setMessages(prevMessages => prevMessages.map(msg => {
      if (!msg.tools || msg.tools.length === 0) return msg
      const tools = msg.tools.map(t => {
        if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
          return { ...t, status: 'running' }
        }
        return t
      })
      return { ...msg, tools }
    }))

    try {
      const res = await fetch(`${API_BASE}/engine/${engineThreadId}/resume`, { method: 'POST' })
      const data = await res.json()

      if (!res.ok) {
        setEngineConflictAlert(data?.detail || "Already one engine is running in this chat. Pause it first before resuming another engine.")
        // Revert optimistic running update
        setMessages(prevMessages => prevMessages.map(msg => {
          if (!msg.tools || msg.tools.length === 0) return msg
          const tools = msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
              return { ...t, status: 'paused' }
            }
            return t
          })
          return { ...msg, tools }
        }))
        return
      }

      if (data.status === 'resumed') {
        setEnginesList(prev => prev.map(e => {
          const eid = e.engine_thread_id || e.engine_id
          if (eid === engineThreadId) return { ...e, status: 'running' }
          if (e.status === 'running') return { ...e, status: 'paused' }
          return e
        }))
        connectToEngineStream(
          engineThreadId,
          displayName,
          toolName,
          engine.progress || engine.nodes || {}
        )
      }
    } catch (err) {
      console.error("Failed to resume engine", err)
      // Revert if resume failed
      setMessages(prevMessages => prevMessages.map(msg => {
        if (!msg.tools || msg.tools.length === 0) return msg
        const tools = msg.tools.map(t => {
          if ((t.engine_thread_id || t.engine_id) === engineThreadId) {
            return { ...t, status: 'paused' }
          }
          return t
        })
        return { ...msg, tools }
      }))
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Send Message + Stream Handler
  // ─────────────────────────────────────────────────────────────────────────

  const sendMessage = async () => {
    if (!input.trim()) return

    const running = getRunningEngine()
    if (running) {
      setEngineConflictAlert("Already one engine is running in this chat. Pause it first to run a second engine.")
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
    
    isNearBottomRef.current = true
    setMessages(prev => [...prev, { role: 'user', content: userMsg }])
    setMessages(prev => [...prev, { role: 'assistant', content: '', tools: [] }])
    setIsStreaming(true)
    setTimeout(() => scrollToBottom(true), 50)

    if (streamAbortControllerRef.current) {
      streamAbortControllerRef.current.abort()
    }
    const controller = new AbortController()
    streamAbortControllerRef.current = controller

    try {
      const response = await fetch(`${API_BASE}/chats/${currentThreadId}/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMsg }),
        signal: controller.signal
      })

      if (!response.ok) {
        let errData = null
        try { errData = await response.json() } catch {}
        setEngineConflictAlert(errData?.detail || "Already one engine is running in this chat. Pause it first to run a second engine.")
        setMessages(prev => prev.slice(0, prev.length - 2))
        return
      }

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
      if (err.name === 'AbortError') return
      console.error("Stream error", err)
      setMessages(prev => {
        if (prev.length === 0) return prev
        const copy = [...prev]
        const last = { ...copy[copy.length - 1] }
        if (last.role === 'assistant' && !last.content) {
          last.content = `⚠️ **Connection Error:** Could not reach the API server (${err.message || 'Network error'}). Please verify the server is running.`
          copy[copy.length - 1] = last
        }
        return copy
      })
    } finally {
      setIsStreaming(false)
      if (streamAbortControllerRef.current === controller) {
        streamAbortControllerRef.current = null
      }
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
      const eid = event.engine_thread_id

      // If there was an existing active engine, mark it as paused in messages
      if (activeEngine && activeEngine.engine_thread_id !== eid) {
        const prevEngine = activeEngine
        const prevStatus = (prevEngine.status === 'done' || prevEngine.status === 'error') ? prevEngine.status : 'paused'
        setMessages(prevMessages => prevMessages.map(msg => {
          if (!msg.tools || msg.tools.length === 0) return msg
          const tools = msg.tools.map(t => {
            if ((t.engine_thread_id || t.engine_id) === prevEngine.engine_thread_id) {
              return { ...t, status: prevStatus, nodes: prevEngine.nodes || t.nodes || {} }
            }
            return t
          })
          return { ...msg, tools }
        }))
      }

      // Initialize node states for this tool
      const toolNodes = TOOL_NODE_MAP[event.tool] || []
      const initialNodeStates = {}
      toolNodes.forEach(n => {
        initialNodeStates[n.key] = { status: 'pending', detail: '' }
      })

      // Attach the engine tool block directly into the current assistant message's tools array
      setMessages(prevMessages => {
        if (prevMessages.length === 0) return prevMessages
        const newMsgs = [...prevMessages]
        let asstIdx = -1
        for (let i = newMsgs.length - 1; i >= 0; i--) {
          if (newMsgs[i].role === 'assistant') {
            asstIdx = i
            break
          }
        }
        if (asstIdx !== -1) {
          const asstMsg = { ...newMsgs[asstIdx] }
          const tools = asstMsg.tools ? [...asstMsg.tools] : []
          if (!tools.some(t => (t.engine_thread_id || t.engine_id) === eid)) {
            tools.push({
              name: event.tool,
              tool_name: event.tool,
              engine_id: eid,
              engine_thread_id: eid,
              status: 'running',
              nodes: initialNodeStates,
              input_data: pendingApproval?.query ? { query: pendingApproval.query } : {},
            })
            asstMsg.tools = tools
            newMsgs[asstIdx] = asstMsg
          }
        }
        return newMsgs
      })

      // Engine just started in the background — update engines list and connect to its SSE stream
      setEnginesList(prev => {
        const exists = prev.some(e => (e.engine_thread_id || e.engine_id) === eid)
        if (exists) {
          return prev.map(e => ((e.engine_thread_id || e.engine_id) === eid ? { ...e, status: 'running' } : (e.status === 'running' ? { ...e, status: 'paused' } : e)))
        }
        return [
          ...prev.map(e => e.status === 'running' ? { ...e, status: 'paused' } : e),
          {
            engine_thread_id: eid,
            tool_name: event.tool,
            engine_name: event.engine_name,
            status: 'running',
            input_data: pendingApproval?.query ? { query: pendingApproval.query } : {},
            created_at: new Date().toISOString(),
          }
        ]
      })

      connectToEngineStream(
        eid,
        event.engine_name,
        event.tool,
        initialNodeStates
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
        if (ENGINE_TOOL_NAMES.includes(event.tool)) {
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
      else if (event.type === 'db_results') {
        // DB query results — render as a formatted table (data goes to frontend, not LLM)
        lastMsg.queryResults = [...(lastMsg.queryResults || []), {
          query: event.query,
          columns: event.columns,
          rows: event.rows,
          total: event.total,
        }]
      }
      else if (event.type === 'stopped') {
        lastMsg.content = (lastMsg.content || '') + '\n\n*Agent stopped by user.*'
      }
      else if (event.type === 'error') {
        lastMsg.content = (lastMsg.content || '') + `\n\n⚠️ **Error:** ${event.message || event.error || 'An unexpected error occurred.'}`
      }
      
      return newMessages
    })
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  const runningEngine = getRunningEngine()
  const isEngineRunning = !!runningEngine

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

        <Link to="/search" className="search-nav-btn">
          <Search size={16} /> Search Engine
        </Link>

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
        {activeThreadId && (
          <div className="main-content-header">
            <div className="main-header-info">
              <span className="main-header-title">{activeThreadId}</span>
              {activeEngine && (activeEngine.status === 'running' || activeEngine.status === 'pausing') && (
                <span className="main-header-engine-running">
                  <Activity size={12} className="spin" />
                  {ENGINE_DISPLAY_NAMES[activeEngine.tool] || activeEngine.tool} running
                </span>
              )}
            </div>
            <button 
              className={`engines-toggle-btn ${isRightPanelOpen ? 'active' : ''}`}
              onClick={() => setIsRightPanelOpen(!isRightPanelOpen)}
              title={isRightPanelOpen ? "Hide Engines Panel" : "Show Engines Panel"}
            >
              <Activity size={14} />
              <span>Engines</span>
              {enginesList.length > 0 && (
                <span className="engines-toggle-count">{enginesList.length}</span>
              )}
            </button>
          </div>
        )}

        {!activeThreadId ? (
          <div className="welcome-screen">
            <ShieldAlert size={48} className="welcome-icon" />
            <h1 className="welcome-title">Welcome to <span>CTI Agent</span></h1>
            <p className="welcome-subtitle">
              Your AI-powered Cyber Threat Intelligence analyst. Ask me to scan IPs, lookup CVEs, or discover vulnerabilities.
            </p>
          </div>
        ) : (
          <div className="chat-area" ref={chatAreaRef} onScroll={handleChatScroll}>

            {messages.map((msg, idx) => (
              <div key={idx} className={`message-wrapper ${msg.role}`}>
                <div className="message-content">
                  <div className={`avatar ${msg.role}`}>
                    {msg.role === 'user' ? 'U' : <ShieldAlert size={18} color="white" />}
                  </div>
                  <div className="message-body">
                    {/* Render tool executions directly in place within the assistant message */}
                    {msg.role === 'assistant' && msg.tools && msg.tools.map((tool, tIdx) => {
                      const toolName = tool.name || tool.tool_name
                      
                      // Engine tools use the full pipeline-style ToolExecutionBlock
                      if (ENGINE_TOOL_NAMES.includes(toolName)) {
                        const isThisActive = activeEngine && (tool.engine_thread_id || tool.engine_id) === activeEngine.engine_thread_id
                        const liveTool = isThisActive ? {
                          ...tool,
                          status: activeEngine.status,
                          nodes: activeEngine.nodes || tool.nodes,
                          error: activeEngine.error || tool.error,
                        } : tool

                        return (
                          <ToolExecutionBlock 
                            key={tool.engine_thread_id || tool.engine_id || tIdx} 
                            tool={liveTool} 
                            onStop={handleStopEngine}
                            onResume={handleResumeEngine} 
                          />
                        )
                      }
                      
                      // DB tools and other tools use the lightweight indicator
                      return <ToolUseIndicator key={`tool-${tIdx}`} tool={tool} />
                    })}

                    {/* Render DB query results as formatted tables */}
                    {msg.queryResults && msg.queryResults.map((result, rIdx) => (
                      <QueryResultsTable key={`qr-${rIdx}`} data={result} />
                    ))}
                    
                    {/* Render markdown text with GFM plugin for tables and client-side links */}
                    {msg.content && (
                      <ReactMarkdown 
                        remarkPlugins={[remarkGfm]}
                        components={{
                          a: ({ href, children, ...props }) => {
                            if (href && (href.startsWith('/') || href.startsWith('#'))) {
                              return <Link to={href} {...props}>{children}</Link>
                            }
                            return <a href={href} target="_blank" rel="noopener noreferrer" {...props}>{children}</a>
                          }
                        }}
                      >
                        {msg.content}
                      </ReactMarkdown>
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

            {/* Fallback Engine Progress Panel only if activeEngine is somehow not inside any message */}
            {activeEngine && !messages.some(m => m.tools?.some(t => (t.engine_thread_id || t.engine_id) === activeEngine.engine_thread_id)) && (
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
              placeholder={isEngineRunning ? "An engine is running (pause it to ask a new query)..." : "Ask CTI Agent to scan an IP or CVE..."}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  if (isEngineRunning) {
                    setEngineConflictAlert("Already one engine is running in this chat. Pause it first to run a second engine.")
                  } else {
                    sendMessage()
                  }
                }
              }}
              disabled={isStreaming || !!pendingApproval}
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
                onClick={() => {
                  if (isEngineRunning) {
                    setEngineConflictAlert("Already one engine is running in this chat. Pause it first to run a second engine.")
                  } else {
                    sendMessage()
                  }
                }}
                disabled={!input.trim() || isStreaming || !!pendingApproval}
              >
                <Send size={16} />
              </button>
            )}
          </div>
        </div>
      </main>

      {/* Right Engines Sidebar */}
      {activeThreadId && isRightPanelOpen && (
        <EnginesSidebar 
          engines={enginesList}
          activeEngine={activeEngine}
          onStop={handleStopEngine}
          onResume={handleResumeEngine}
          onClose={() => setIsRightPanelOpen(false)}
        />
      )}

      {/* Engine Conflict Alert Modal */}
      {engineConflictAlert && (
        <div className="engine-conflict-overlay" onClick={() => setEngineConflictAlert(null)}>
          <div className="engine-conflict-modal" onClick={e => e.stopPropagation()}>
            <div className="engine-conflict-header">
              <div className="engine-conflict-icon-wrap">
                <AlertTriangle size={24} color="#f59e0b" />
              </div>
              <div className="engine-conflict-title-group">
                <h3>Engine Conflict</h3>
                <span className="engine-conflict-badge">Action Blocked</span>
              </div>
              <button 
                className="engine-conflict-close" 
                onClick={() => setEngineConflictAlert(null)}
                title="Close"
              >
                <X size={18} />
              </button>
            </div>
            <div className="engine-conflict-body">
              <p>{engineConflictAlert}</p>
            </div>
            <div className="engine-conflict-footer">
              <button 
                className="engine-conflict-btn"
                onClick={() => setEngineConflictAlert(null)}
              >
                OK, Understood
              </button>
            </div>
          </div>
        </div>
      )}
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
  const allDynamicKeys = Object.keys(engine.nodes || {}).filter(key => !allNodeKeys.has(key) && key !== 'processing')
  const hasWorkerSlots = allDynamicKeys.some(k => k.startsWith('nmap_worker_'))

  let dynamicNodes = allDynamicKeys
    .filter(key => {
      if (hasWorkerSlots && key.startsWith('nmap_') && !key.startsWith('nmap_worker_')) {
        return false
      }
      return true
    })
    .map(key => {
      let label = key
      if (key.startsWith('nmap_worker_')) {
        const num = key.replace('nmap_worker_', '')
        label = `Worker ${num}`
      } else if (key.startsWith('nmap_')) {
        label = key.replace('nmap_', 'Nmap: ').replace(/_/g, '.')
      }
      return { key, label }
    })
    .sort((a, b) => {
      if (a.key.startsWith('nmap_worker_') && b.key.startsWith('nmap_worker_')) {
        const numA = parseInt(a.key.replace('nmap_worker_', ''), 10) || 0
        const numB = parseInt(b.key.replace('nmap_worker_', ''), 10) || 0
        return numA - numB
      }
      return a.key.localeCompare(b.key)
    })

  if (!hasWorkerSlots && dynamicNodes.length > 5) {
    dynamicNodes = dynamicNodes.slice(0, 5)
  }
  
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
            <button className="engine-stop-btn" onClick={() => onStop(engine)} title="Pause Engine">
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
 * Helper to extract human-readable query text from an engine's input data
 */
function getEngineQueryText(engine) {
  if (!engine) return ''
  const inp = engine.input_data || engine.input || {}
  if (inp.query) return inp.query
  if (inp.ip_addresses && Array.isArray(inp.ip_addresses)) return inp.ip_addresses.join(', ')
  if (inp.cve_ids && Array.isArray(inp.cve_ids)) return inp.cve_ids.join(', ')
  if (typeof inp === 'string') return inp
  return engine.query || ''
}


/**
 * Engines Sidebar — Right panel displaying all engine runs for the active chat
 */
function EnginesSidebar({
  engines,
  activeEngine,
  onStop,
  onResume,
  onClose,
}) {
  return (
    <aside className="engines-sidebar">
      <div className="engines-sidebar-header">
        <div className="engines-sidebar-title">
          <TerminalSquare size={16} />
          <span>Engine Runs</span>
          {engines.length > 0 && (
            <span className="engines-badge">{engines.length}</span>
          )}
        </div>
        <button 
          className="engines-collapse-btn" 
          onClick={onClose} 
          title="Collapse Engines Panel"
        >
          <ChevronRight size={18} />
        </button>
      </div>

      <div className="engines-sidebar-content">
        {engines.length === 0 ? (
          <div className="engines-empty-state">
            <Activity size={32} className="engines-empty-icon" />
            <span>No engine runs yet</span>
            <p>Background scans started in this investigation will appear here.</p>
          </div>
        ) : (
          <div className="engines-tickets-list">
            {engines.map((engine, idx) => {
              const engineId = engine.engine_thread_id || engine.engine_id
              const isActive = activeEngine && (activeEngine.engine_thread_id === engineId)
              const currentStatus = isActive ? activeEngine.status : (engine.status || 'done')
              const toolName = engine.tool_name || engine.tool || engine.name
              const displayName = ENGINE_DISPLAY_NAMES[toolName] || engine.engine_name || toolName
              const queryText = getEngineQueryText(engine)
              
              const isRunning = currentStatus === 'running'
              const isPausing = currentStatus === 'pausing'
              const isPaused = currentStatus === 'paused'
              const isDone = currentStatus === 'done'
              const isError = currentStatus === 'error'

              return (
                <div key={engineId || idx} className={`engine-ticket ${currentStatus}`}>
                  <div className="engine-ticket-top">
                    <div className="engine-ticket-name">
                      <TerminalSquare size={14} />
                      <span>{displayName}</span>
                    </div>
                    <div className={`engine-ticket-badge ${currentStatus}`}>
                      {isRunning && <><Activity size={10} className="spin" /> Running</>}
                      {isPausing && <><Activity size={10} className="spin" /> Stopping...</>}
                      {isPaused && <><Pause size={10} /> Paused</>}
                      {isDone && <><CheckCircle2 size={10} /> Done</>}
                      {isError && <><AlertTriangle size={10} /> Error</>}
                    </div>
                  </div>

                  {queryText && (
                    <div className="engine-ticket-query" title={queryText}>
                      "{queryText}"
                    </div>
                  )}

                  <div className="engine-ticket-actions">
                    {isRunning && (
                      <button 
                        className="ticket-btn stop" 
                        onClick={() => onStop(engine)} 
                        title="Pause Engine"
                      >
                        <Pause size={12} /> Stop
                      </button>
                    )}
                    {isPausing && (
                      <button 
                        className="ticket-btn stop disabled" 
                        disabled 
                        title="Stopping Engine..."
                      >
                        <Activity size={12} className="spin" /> Stopping...
                      </button>
                    )}
                    {isPaused && (
                      <button 
                        className="ticket-btn resume" 
                        onClick={() => onResume(engine)} 
                        title="Resume Engine"
                      >
                        <Play size={12} /> Resume
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </aside>
  )
}


/**
 * Renders a stylized block showing the engine pipeline with real-time node progress.
 * (Used for historical tool calls loaded from DB)
 */
function ToolExecutionBlock({ tool, onStop, onResume }) {
  const toolName = tool.name || tool.tool_name
  const predefinedNodes = TOOL_NODE_MAP[toolName] || [
    { key: 'processing', label: 'Processing' },
  ]
  const allNodeKeys = new Set(predefinedNodes.map(n => n.key))
  const allDynamicKeys = Object.keys(tool.nodes || {}).filter(key => !allNodeKeys.has(key) && key !== 'processing')
  const hasWorkerSlots = allDynamicKeys.some(k => k.startsWith('nmap_worker_'))

  let dynamicNodes = allDynamicKeys
    .filter(key => {
      if (hasWorkerSlots && key.startsWith('nmap_') && !key.startsWith('nmap_worker_')) {
        return false
      }
      return true
    })
    .map(key => {
      let label = key
      if (key.startsWith('nmap_worker_')) {
        const num = key.replace('nmap_worker_', '')
        label = `Worker ${num}`
      } else if (key.startsWith('nmap_')) {
        label = key.replace('nmap_', 'Nmap: ').replace(/_/g, '.')
      }
      return { key, label }
    })
    .sort((a, b) => {
      if (a.key.startsWith('nmap_worker_') && b.key.startsWith('nmap_worker_')) {
        const numA = parseInt(a.key.replace('nmap_worker_', ''), 10) || 0
        const numB = parseInt(b.key.replace('nmap_worker_', ''), 10) || 0
        return numA - numB
      }
      return a.key.localeCompare(b.key)
    })

  if (!hasWorkerSlots && dynamicNodes.length > 5) {
    dynamicNodes = dynamicNodes.slice(0, 5)
  }
  
  const nodeList = [...predefinedNodes, ...dynamicNodes]

  const isRunning = tool.status === 'running'
  const isPausing = tool.status === 'pausing'
  const isPaused = tool.status === 'paused'
  const isDone = tool.status === 'done'
  const isError = tool.status === 'error'

  return (
    <div className={`tool-block ${tool.status}`}>
      <div className="tool-header">
        <div className="tool-title">
          <TerminalSquare size={16} />
          {ENGINE_DISPLAY_NAMES[toolName] || toolName}
        </div>
        <div className="tool-controls">
          {isRunning && onStop && (
            <button 
              className="tool-stop-btn" 
              onClick={() => onStop(tool)} 
              title="Pause Engine"
            >
              <Pause size={13} /> Stop
            </button>
          )}
          {isPausing && (
            <button 
              className="tool-stop-btn disabled" 
              disabled 
              title="Stopping Engine..."
            >
              <Activity size={13} className="spin" /> Stopping...
            </button>
          )}
          {isPaused && onResume && (
            <button 
              className="tool-resume-btn" 
              onClick={() => onResume(tool)} 
              title="Resume Engine"
            >
              <Play size={13} /> Resume
            </button>
          )}
          <div className={`tool-status-badge ${tool.status}`}>
            {isRunning ? (
              <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
                <Activity size={12} className="spin" /> Running Engine
              </span>
            ) : isPausing ? (
              <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
                <Activity size={12} className="spin" /> Stopping...
              </span>
            ) : isPaused ? (
              <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
                <Pause size={12} /> Paused
              </span>
            ) : isError ? (
              <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
                <AlertTriangle size={12} /> Error
              </span>
            ) : (
              <span style={{display: 'flex', alignItems: 'center', gap: '6px'}}>
                <CheckCircle2 size={12} /> Completed
              </span>
            )}
          </div>
        </div>
      </div>
      
      <div className="tool-nodes">
        {nodeList.map((nodeDef, index) => {
          const nodeState = tool.nodes?.[nodeDef.key] || { status: 'pending', detail: '' }
          
          let displayStatus = nodeState.status
          if (isDone) displayStatus = 'done'
          if (isPaused && displayStatus === 'running') displayStatus = 'paused'
          if (isPausing && displayStatus === 'running') displayStatus = 'running'

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


/**
 * Lightweight tool use indicator for non-engine tools (DB queries, schema lookups, etc.)
 * Shows a compact, collapsible card similar to modern chatbot tool indicators.
 */
function ToolUseIndicator({ tool }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const toolName = tool.name || tool.tool_name
  const displayInfo = TOOL_DISPLAY_NAMES[toolName] || { running: toolName, done: toolName }
  const isRunning = tool.status === 'running'
  const displayName = isRunning ? displayInfo.running : displayInfo.done

  // Extract readable input summary
  const getInputSummary = () => {
    if (!tool.input) return null
    if (tool.input.query) return tool.input.query
    if (tool.input.table_names) return tool.input.table_names
    if (typeof tool.input === 'string') return tool.input
    const entries = Object.entries(tool.input)
    if (entries.length === 0) return null
    return JSON.stringify(tool.input, null, 2)
  }

  const inputSummary = getInputSummary()
  const hasDetails = inputSummary || tool.output

  return (
    <div
      className={`tool-use-indicator ${tool.status}`}
      onClick={() => hasDetails && setIsExpanded(!isExpanded)}
      style={{ cursor: hasDetails ? 'pointer' : 'default' }}
    >
      <div className="tool-use-header">
        <div className="tool-use-icon">
          {isRunning
            ? <Activity size={14} className="spin" />
            : <CheckCircle2 size={14} />
          }
        </div>
        <Database size={14} className="tool-use-db-icon" />
        <span className="tool-use-name">
          {displayName}{isRunning ? '...' : ''}
        </span>
        {hasDetails && (
          <ChevronRight
            size={14}
            className={`tool-use-chevron ${isExpanded ? 'expanded' : ''}`}
          />
        )}
      </div>
      {isExpanded && hasDetails && (
        <div className="tool-use-details">
          {inputSummary && (
            <div className="tool-use-section">
              <span className="tool-use-label">Input</span>
              <code className="tool-use-code">{inputSummary}</code>
            </div>
          )}
          {tool.output && (
            <div className="tool-use-section">
              <span className="tool-use-label">Result</span>
              <pre className="tool-use-code">
                {typeof tool.output === 'string' && tool.output.length > 800
                  ? tool.output.substring(0, 800) + '\n... (truncated)'
                  : tool.output}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}


/**
 * Formatted table for DB query results.
 * Shows a collapsible card with the SQL query and a styled results table.
 * Data comes directly from the backend (not through the LLM).
 */
function QueryResultsTable({ data }) {
  const [isExpanded, setIsExpanded] = useState(true)
  const { query, columns, rows, total } = data

  return (
    <div className="query-results-card">
      <div className="query-results-header" onClick={() => setIsExpanded(!isExpanded)}>
        <Database size={15} className="query-results-icon" />
        <span className="query-results-title">
          Query Results
          <span className="query-results-count">{total} row{total !== 1 ? 's' : ''}</span>
        </span>
        <ChevronRight
          size={14}
          className={`query-results-chevron ${isExpanded ? 'expanded' : ''}`}
        />
      </div>
      {isExpanded && (
        <div className="query-results-body">
          <div className="query-results-sql">
            <code>{query}</code>
          </div>
          {columns.length > 0 && rows.length > 0 ? (
            <div className="query-results-table-wrap">
              <table className="query-results-table">
                <thead>
                  <tr>
                    {columns.map((col, i) => (
                      <th key={i}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row, i) => (
                    <tr key={i}>
                      {row.map((val, j) => (
                        <td key={j}>{val ?? '—'}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="query-results-empty">No rows returned</div>
          )}
        </div>
      )}
    </div>
  )
}
