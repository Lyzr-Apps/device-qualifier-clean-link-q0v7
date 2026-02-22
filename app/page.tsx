'use client'

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { callAIAgent, type AIAgentResponse } from '@/lib/aiAgent'
import { copyToClipboard } from '@/lib/clipboard'
import { cn, generateUUID } from '@/lib/utils'
import { KnowledgeBaseUpload } from '@/components/KnowledgeBaseUpload'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { HiOutlineBookOpen, HiOutlineShieldCheck, HiOutlineDocumentText, HiOutlineClipboardCopy, HiOutlineSearch, HiOutlineLightningBolt, HiOutlineChevronDown, HiOutlineChevronUp, HiOutlineCheck, HiOutlineRefresh, HiOutlinePaperAirplane, HiOutlineExclamationCircle, HiOutlineInformationCircle } from 'react-icons/hi'

// --- Constants ---
const KNOWLEDGE_AGENT_ID = '699a59b2f9f218c9deafb88e'
const ANALYZER_AGENT_ID = '699a59b2a08d53aec7db312e'
const REPORT_AGENT_ID = '699a59c9e2098a3529de8229'
const RAG_ID = '699a5979e12ce1682031312c'

// --- Types ---
interface ChatMessage {
  id: string
  role: 'user' | 'agent'
  content: string
  sources?: string
  relatedTopics?: string[]
  timestamp: string
}

interface AnalysisResult {
  severity: string
  severity_rationale: string
  remediation: string
  override_justification: string
  related_tests: string
  additional_context: string
  timestamp: string
  input_summary: string
}

interface ReportResult {
  executive_summary: string
  detailed_narrative: string
  conditions: string
  word_count: string
}

// --- Utility: Parse agent result ---
function parseAgentResult(result: AIAgentResponse): Record<string, any> {
  const raw = result?.response?.result
  if (!raw) return {}
  if (typeof raw === 'string') {
    try { return JSON.parse(raw) } catch { return { text: raw } }
  }
  return raw
}

// --- Markdown Renderer ---
function formatInline(text: string) {
  const parts = text.split(/\*\*(.*?)\*\*/g)
  if (parts.length === 1) {
    const codeParts = text.split(/`(.*?)`/g)
    if (codeParts.length === 1) return text
    return codeParts.map((part, i) =>
      i % 2 === 1 ? (
        <code key={i} className="px-1.5 py-0.5 rounded bg-muted text-sm font-mono text-accent-foreground">{part}</code>
      ) : (
        part
      )
    )
  }
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <strong key={i} className="font-semibold">{part}</strong>
    ) : (
      <React.Fragment key={i}>{formatInline(part) as any}</React.Fragment>
    )
  )
}

function renderMarkdown(text: string) {
  if (!text) return null
  return (
    <div className="space-y-2">
      {text.split('\n').map((line, i) => {
        if (line.startsWith('### '))
          return <h4 key={i} className="font-semibold text-sm mt-3 mb-1">{line.slice(4)}</h4>
        if (line.startsWith('## '))
          return <h3 key={i} className="font-semibold text-base mt-3 mb-1">{line.slice(3)}</h3>
        if (line.startsWith('# '))
          return <h2 key={i} className="font-bold text-lg mt-4 mb-2">{line.slice(2)}</h2>
        if (line.startsWith('- ') || line.startsWith('* '))
          return <li key={i} className="ml-4 list-disc text-sm">{formatInline(line.slice(2))}</li>
        if (/^\d+\.\s/.test(line))
          return <li key={i} className="ml-4 list-decimal text-sm">{formatInline(line.replace(/^\d+\.\s/, ''))}</li>
        if (!line.trim()) return <div key={i} className="h-1" />
        return <p key={i} className="text-sm leading-relaxed">{formatInline(line)}</p>
      })}
    </div>
  )
}

// --- Copy Button Component ---
function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = async () => {
    const success = await copyToClipboard(text)
    if (success) {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }
  return (
    <Button variant="ghost" size="sm" onClick={handleCopy} className="h-7 gap-1.5 text-xs text-muted-foreground hover:text-foreground">
      {copied ? <HiOutlineCheck className="h-3.5 w-3.5 text-green-400" /> : <HiOutlineClipboardCopy className="h-3.5 w-3.5" />}
      {label && <span>{copied ? 'Copied' : label}</span>}
    </Button>
  )
}

// --- Severity Badge ---
function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity ?? '').toLowerCase()
  let colorClass = 'bg-muted text-muted-foreground'
  if (s.includes('critical')) colorClass = 'bg-red-900/60 text-red-300 border-red-700/50'
  else if (s.includes('high')) colorClass = 'bg-orange-900/60 text-orange-300 border-orange-700/50'
  else if (s.includes('medium')) colorClass = 'bg-yellow-900/60 text-yellow-300 border-yellow-700/50'
  else if (s.includes('low')) colorClass = 'bg-green-900/60 text-green-300 border-green-700/50'
  return <Badge className={cn('text-sm px-3 py-1 border', colorClass)}>{severity || 'Unknown'}</Badge>
}

// --- Sample Data ---
const SAMPLE_CHAT_MESSAGES: ChatMessage[] = [
  {
    id: 'sample-1',
    role: 'user',
    content: 'What tests are automated in the EDQ process?',
    timestamp: '10:30 AM',
  },
  {
    id: 'sample-2',
    role: 'agent',
    content: '## Automated EDQ Tests\n\nThe EDQ process includes several automated test categories:\n\n- **Port Scanning** - Nmap-based network port discovery and service identification\n- **TLS/SSL Analysis** - Certificate validation, cipher suite testing, and protocol version checks\n- **SSH Configuration** - Key exchange algorithms, authentication methods, and protocol compliance\n- **BACnet Discovery** - Building automation protocol device enumeration\n- **Credential Testing** - Default credential verification against known device databases\n\nEach test generates structured output that feeds into the **Finding Analyzer** for severity classification and the **Report Draftor** for narrative generation.',
    sources: 'EDQ Test Framework v3.2, Automated Testing Procedures Manual',
    relatedTopics: ['Port scanning methodology', 'TLS cipher suites', 'BACnet protocol'],
    timestamp: '10:30 AM',
  },
]

const SAMPLE_ANALYSIS: AnalysisResult = {
  severity: 'High',
  severity_rationale: 'Open administrative ports (22, 443, 80) expose the device to potential unauthorized access. The presence of default SSH configurations increases the attack surface significantly.',
  remediation: '## Remediation Steps\n\n1. **Disable unused ports** - Close ports 80 and any non-essential services\n2. **Harden SSH** - Disable password authentication, use key-based auth only\n3. **Update TLS** - Ensure TLS 1.2+ is enforced on port 443\n4. **Network segmentation** - Place device behind a dedicated VLAN\n5. **Access control** - Implement IP whitelisting for management interfaces',
  override_justification: 'This finding may be overridden if the following conditions are met:\n- Device is on an isolated management network with restricted access\n- Compensating controls (firewall rules, IDS monitoring) are documented\n- Risk acceptance is signed by the system owner',
  related_tests: 'EDQ-PS-001 (Port Scan), EDQ-SSH-003 (SSH Config), EDQ-TLS-002 (TLS Audit)',
  additional_context: 'Consider running a follow-up credential test (EDQ-CRED-001) to verify no default passwords are active on exposed services.',
  timestamp: '10:35 AM',
  input_summary: 'Port Scan / Pelco device',
}

const SAMPLE_REPORT: ReportResult = {
  executive_summary: 'The Pelco Sarix IX30DN-E network camera at 192.168.1.100 underwent comprehensive Electronic Device Qualification testing. The device demonstrated compliance with core security requirements but exhibited vulnerabilities in its TLS configuration and default credential management. A conditional pass is recommended pending remediation of identified findings.',
  detailed_narrative: '## Test Environment\n\nThe device under test (DUT) is a Pelco Sarix IX30DN-E IP camera manufactured by Pelco, operating on firmware version 3.2.1. Testing was conducted on the facility network at IP address 192.168.1.100.\n\n## Port Scan Results\n\nNetwork port scanning revealed three open ports: TCP/80 (HTTP), TCP/443 (HTTPS), and TCP/554 (RTSP). The HTTP service redirects to HTTPS, which is a positive security measure.\n\n## TLS/SSL Assessment\n\nThe device supports TLS 1.2 but also permits TLS 1.0 connections, which should be disabled. The certificate is self-signed with a 2048-bit RSA key.\n\n## Recommendations\n\n- Disable TLS 1.0 support\n- Replace self-signed certificate with CA-issued certificate\n- Change all default credentials',
  conditions: '1. TLS 1.0 must be disabled within 30 days\n2. Default credentials must be changed before deployment\n3. Self-signed certificate must be replaced with CA-issued certificate within 60 days',
  word_count: '247',
}

// --- ErrorBoundary ---
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: string }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false, error: '' }
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error: error.message }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
          <div className="text-center p-8 max-w-md">
            <h2 className="text-xl font-semibold mb-2">Something went wrong</h2>
            <p className="text-muted-foreground mb-4 text-sm">{this.state.error}</p>
            <button onClick={() => this.setState({ hasError: false, error: '' })} className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm">
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

// =================================================================
// MAIN PAGE
// =================================================================
export default function Page() {
  // --- Navigation ---
  const [activeTab, setActiveTab] = useState<'knowledge' | 'analyzer' | 'report'>('knowledge')
  const [sampleData, setSampleData] = useState(false)
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null)

  // --- Session IDs (generated once) ---
  const [sessionIds] = useState(() => ({
    knowledge: generateUUID(),
    analyzer: generateUUID(),
    report: generateUUID(),
  }))

  // --- Knowledge Assistant State ---
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const [chatError, setChatError] = useState<string | null>(null)
  const [kbOpen, setKbOpen] = useState(false)
  const chatEndRef = useRef<HTMLDivElement>(null)

  // --- Analyzer State ---
  const [analyzerForm, setAnalyzerForm] = useState({
    testCategory: '',
    deviceType: '',
    findingDetails: '',
  })
  const [analyzerResult, setAnalyzerResult] = useState<AnalysisResult | null>(null)
  const [analyzerLoading, setAnalyzerLoading] = useState(false)
  const [analyzerError, setAnalyzerError] = useState<string | null>(null)
  const [analyzerHistory, setAnalyzerHistory] = useState<AnalysisResult[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)

  // --- Report Draftor State ---
  const [reportForm, setReportForm] = useState({
    deviceName: '',
    ipAddress: '',
    manufacturer: '',
    systemType: '',
    overallResult: '',
    keyFindings: '',
    audience: 'Technical',
  })
  const [reportResult, setReportResult] = useState<ReportResult | null>(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)
  const [reportTab, setReportTab] = useState('executive')

  // --- Scroll chat to bottom ---
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages, chatLoading])

  // --- Get displayed chat messages ---
  const displayedChatMessages = sampleData && chatMessages.length === 0 ? SAMPLE_CHAT_MESSAGES : chatMessages
  const displayedAnalysis = sampleData && !analyzerResult ? SAMPLE_ANALYSIS : analyzerResult
  const displayedReport = sampleData && !reportResult ? SAMPLE_REPORT : reportResult

  // --- Knowledge Assistant: Send Message ---
  const handleSendChat = useCallback(async (messageOverride?: string) => {
    const message = messageOverride ?? chatInput.trim()
    if (!message) return
    setChatInput('')
    setChatError(null)
    const userMsg: ChatMessage = {
      id: generateUUID(),
      role: 'user',
      content: message,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }
    setChatMessages(prev => [...prev, userMsg])
    setChatLoading(true)
    setActiveAgentId(KNOWLEDGE_AGENT_ID)
    try {
      const result = await callAIAgent(message, KNOWLEDGE_AGENT_ID, { session_id: sessionIds.knowledge })
      if (result.success) {
        const parsed = parseAgentResult(result)
        const answer = parsed?.answer ?? parsed?.text ?? result?.response?.message ?? 'No response received.'
        const sources = parsed?.sources ?? ''
        const relatedRaw = parsed?.related_topics ?? ''
        const relatedTopics = typeof relatedRaw === 'string' && relatedRaw.length > 0
          ? relatedRaw.split(',').map((t: string) => t.trim()).filter(Boolean)
          : Array.isArray(relatedRaw) ? relatedRaw : []
        const agentMsg: ChatMessage = {
          id: generateUUID(),
          role: 'agent',
          content: answer,
          sources: sources,
          relatedTopics: relatedTopics,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        }
        setChatMessages(prev => [...prev, agentMsg])
      } else {
        setChatError(result?.error ?? 'Failed to get response from Knowledge Agent.')
      }
    } catch (err) {
      setChatError('Network error. Please try again.')
    } finally {
      setChatLoading(false)
      setActiveAgentId(null)
    }
  }, [chatInput, sessionIds.knowledge])

  // --- Analyzer: Analyze Finding ---
  const handleAnalyze = useCallback(async () => {
    if (!analyzerForm.findingDetails.trim()) return
    setAnalyzerLoading(true)
    setAnalyzerError(null)
    setAnalyzerResult(null)
    setActiveAgentId(ANALYZER_AGENT_ID)
    const message = `Analyze the following EDQ finding:\nTest Category: ${analyzerForm.testCategory || 'Not specified'}\nDevice Type: ${analyzerForm.deviceType || 'Not specified'}\nFinding Details:\n${analyzerForm.findingDetails}`
    try {
      const result = await callAIAgent(message, ANALYZER_AGENT_ID, { session_id: sessionIds.analyzer })
      if (result.success) {
        const parsed = parseAgentResult(result)
        const analysisResult: AnalysisResult = {
          severity: parsed?.severity ?? 'Unknown',
          severity_rationale: parsed?.severity_rationale ?? '',
          remediation: parsed?.remediation ?? '',
          override_justification: parsed?.override_justification ?? '',
          related_tests: parsed?.related_tests ?? '',
          additional_context: parsed?.additional_context ?? '',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          input_summary: `${analyzerForm.testCategory || 'General'} / ${analyzerForm.deviceType || 'Unknown device'}`,
        }
        setAnalyzerResult(analysisResult)
        setAnalyzerHistory(prev => [analysisResult, ...prev])
      } else {
        setAnalyzerError(result?.error ?? 'Failed to analyze finding.')
      }
    } catch (err) {
      setAnalyzerError('Network error. Please try again.')
    } finally {
      setAnalyzerLoading(false)
      setActiveAgentId(null)
    }
  }, [analyzerForm, sessionIds.analyzer])

  // --- Report Draftor: Generate Narrative ---
  const handleGenerateReport = useCallback(async () => {
    if (!reportForm.deviceName.trim() && !reportForm.keyFindings.trim()) return
    setReportLoading(true)
    setReportError(null)
    setReportResult(null)
    setActiveAgentId(REPORT_AGENT_ID)
    const message = `Generate an EDQ report narrative with the following details:\nDevice Name: ${reportForm.deviceName || 'Not specified'}\nIP Address: ${reportForm.ipAddress || 'Not specified'}\nManufacturer: ${reportForm.manufacturer || 'Not specified'}\nSystem Type: ${reportForm.systemType || 'Not specified'}\nOverall Result: ${reportForm.overallResult || 'Not specified'}\nAudience: ${reportForm.audience}\nKey Findings:\n${reportForm.keyFindings}`
    try {
      const result = await callAIAgent(message, REPORT_AGENT_ID, { session_id: sessionIds.report })
      if (result.success) {
        const parsed = parseAgentResult(result)
        const report: ReportResult = {
          executive_summary: parsed?.executive_summary ?? '',
          detailed_narrative: parsed?.detailed_narrative ?? '',
          conditions: parsed?.conditions ?? '',
          word_count: parsed?.word_count ?? '',
        }
        setReportResult(report)
      } else {
        setReportError(result?.error ?? 'Failed to generate report.')
      }
    } catch (err) {
      setReportError('Network error. Please try again.')
    } finally {
      setReportLoading(false)
      setActiveAgentId(null)
    }
  }, [reportForm, sessionIds.report])

  // --- Navigation Items ---
  const navItems = [
    { key: 'knowledge' as const, label: 'Knowledge Assistant', icon: HiOutlineBookOpen, agentId: KNOWLEDGE_AGENT_ID },
    { key: 'analyzer' as const, label: 'Result Analyzer', icon: HiOutlineShieldCheck, agentId: ANALYZER_AGENT_ID },
    { key: 'report' as const, label: 'Report Draftor', icon: HiOutlineDocumentText, agentId: REPORT_AGENT_ID },
  ]

  const SUGGESTED_QUESTIONS = [
    'What tests are automated?',
    'How does dual-network Docker work?',
    'Explain the STRIDE threat model',
    'What tools does EDQ use?',
  ]

  return (
    <ErrorBoundary>
      <div className="flex h-screen bg-background text-foreground overflow-hidden">
        {/* ===================== SIDEBAR ===================== */}
        <aside className="w-[260px] flex-shrink-0 flex flex-col bg-[hsl(220,16%,14%)] border-r border-border">
          {/* Branding */}
          <div className="px-5 py-5 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-accent/20 flex items-center justify-center">
              <HiOutlineShieldCheck className="h-5 w-5 text-accent-foreground" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-foreground">EDQ Assistant</h1>
              <p className="text-[10px] text-muted-foreground">Electronic Device Qualification</p>
            </div>
          </div>

          <Separator className="opacity-50" />

          {/* Navigation */}
          <nav className="flex-1 px-3 py-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = activeTab === item.key
              return (
                <button
                  key={item.key}
                  onClick={() => setActiveTab(item.key)}
                  className={cn(
                    'w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 text-left',
                    isActive
                      ? 'bg-[hsl(220,16%,20%)] text-foreground border-l-2 border-l-[hsl(213,32%,52%)]'
                      : 'text-muted-foreground hover:text-foreground hover:bg-[hsl(220,16%,18%)]'
                  )}
                >
                  <Icon className={cn('h-4.5 w-4.5 flex-shrink-0', isActive ? 'text-[hsl(213,32%,52%)]' : '')} />
                  <span>{item.label}</span>
                  {activeAgentId === item.agentId && (
                    <span className="ml-auto w-2 h-2 rounded-full bg-[hsl(213,32%,52%)] animate-pulse" />
                  )}
                </button>
              )
            })}
          </nav>

          {/* Sample Data Toggle */}
          <div className="px-5 py-3 border-t border-border">
            <div className="flex items-center justify-between">
              <Label htmlFor="sample-toggle" className="text-xs text-muted-foreground cursor-pointer">Sample Data</Label>
              <Switch id="sample-toggle" checked={sampleData} onCheckedChange={setSampleData} />
            </div>
          </div>

          {/* KB Upload (visible only on Knowledge tab) */}
          {activeTab === 'knowledge' && (
            <div className="px-3 pb-3 border-t border-border">
              <Collapsible open={kbOpen} onOpenChange={setKbOpen}>
                <CollapsibleTrigger asChild>
                  <button className="w-full flex items-center justify-between px-2 py-2.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                    <span>Knowledge Base</span>
                    {kbOpen ? <HiOutlineChevronUp className="h-3.5 w-3.5" /> : <HiOutlineChevronDown className="h-3.5 w-3.5" />}
                  </button>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <KnowledgeBaseUpload ragId={RAG_ID} className="mt-1" />
                </CollapsibleContent>
              </Collapsible>
            </div>
          )}

          {/* Agent Status */}
          <div className="px-5 py-3 border-t border-border">
            <p className="text-[10px] text-muted-foreground mb-2 uppercase tracking-wider font-medium">Agents</p>
            <div className="space-y-1.5">
              {navItems.map((item) => (
                <div key={item.key} className="flex items-center gap-2">
                  <span className={cn('w-1.5 h-1.5 rounded-full', activeAgentId === item.agentId ? 'bg-[hsl(213,32%,52%)] animate-pulse' : 'bg-muted-foreground/40')} />
                  <span className="text-[10px] text-muted-foreground truncate">{item.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Version */}
          <div className="px-5 py-3 border-t border-border">
            <p className="text-[10px] text-muted-foreground">EDQ Assistant v1.0</p>
          </div>
        </aside>

        {/* ===================== MAIN CONTENT ===================== */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {/* ========== KNOWLEDGE ASSISTANT ========== */}
          {activeTab === 'knowledge' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Header */}
              <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-card/50">
                <div>
                  <h2 className="text-lg font-semibold">Knowledge Assistant</h2>
                  <p className="text-xs text-muted-foreground">Ask questions about EDQ processes, standards, and procedures</p>
                </div>
              </div>

              {/* Chat Messages */}
              <ScrollArea className="flex-1 px-6 py-4">
                <div className="max-w-3xl mx-auto space-y-4">
                  {displayedChatMessages.length === 0 && !chatLoading && (
                    <div className="flex flex-col items-center justify-center py-20 space-y-6">
                      <div className="w-16 h-16 rounded-2xl bg-accent/10 flex items-center justify-center">
                        <HiOutlineBookOpen className="h-8 w-8 text-muted-foreground" />
                      </div>
                      <div className="text-center space-y-2">
                        <h3 className="text-lg font-medium text-foreground">Ask the EDQ Knowledge Base</h3>
                        <p className="text-sm text-muted-foreground max-w-sm">Get instant answers about testing procedures, standards, and device qualification processes.</p>
                      </div>
                      <div className="flex flex-wrap gap-2 justify-center max-w-lg">
                        {SUGGESTED_QUESTIONS.map((q) => (
                          <button
                            key={q}
                            onClick={() => handleSendChat(q)}
                            className="px-3 py-1.5 rounded-full border border-border text-xs text-muted-foreground hover:text-foreground hover:border-[hsl(213,32%,52%)] hover:bg-[hsl(220,16%,20%)] transition-all duration-200"
                          >
                            {q}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {displayedChatMessages.map((msg) => (
                    <div key={msg.id} className={cn('flex', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
                      <div className={cn('max-w-[85%] space-y-2', msg.role === 'user' ? 'items-end' : 'items-start')}>
                        <div className={cn(
                          'rounded-xl px-4 py-3',
                          msg.role === 'user'
                            ? 'bg-[hsl(213,32%,52%)] text-white rounded-br-sm'
                            : 'bg-card border border-border rounded-bl-sm'
                        )}>
                          {msg.role === 'agent' ? (
                            <div className="space-y-3">
                              <div className="flex items-center gap-2 mb-2">
                                <div className="w-5 h-5 rounded bg-accent/20 flex items-center justify-center">
                                  <HiOutlineShieldCheck className="h-3 w-3 text-[hsl(213,32%,52%)]" />
                                </div>
                                <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">EDQ Knowledge Agent</span>
                              </div>
                              {renderMarkdown(msg.content)}
                            </div>
                          ) : (
                            <p className="text-sm">{msg.content}</p>
                          )}
                        </div>

                        {/* Sources */}
                        {msg.role === 'agent' && msg.sources && (
                          <Collapsible>
                            <CollapsibleTrigger asChild>
                              <button className="flex items-center gap-1.5 text-[10px] text-muted-foreground hover:text-foreground transition-colors px-1">
                                <HiOutlineInformationCircle className="h-3 w-3" />
                                <span>Sources</span>
                                <HiOutlineChevronDown className="h-3 w-3" />
                              </button>
                            </CollapsibleTrigger>
                            <CollapsibleContent>
                              <div className="mt-1 px-3 py-2 rounded-lg bg-muted/50 text-xs text-muted-foreground">
                                {msg.sources}
                              </div>
                            </CollapsibleContent>
                          </Collapsible>
                        )}

                        {/* Related Topics */}
                        {msg.role === 'agent' && Array.isArray(msg.relatedTopics) && msg.relatedTopics.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 px-1">
                            {msg.relatedTopics.map((topic, idx) => (
                              <button
                                key={idx}
                                onClick={() => handleSendChat(topic)}
                                className="inline-flex items-center px-2 py-0.5 rounded-full border border-border text-[10px] text-muted-foreground hover:text-foreground hover:border-[hsl(213,32%,52%)] transition-colors"
                              >
                                {topic}
                              </button>
                            ))}
                          </div>
                        )}

                        <span className="text-[10px] text-muted-foreground px-1">{msg.timestamp}</span>
                      </div>
                    </div>
                  ))}

                  {chatLoading && (
                    <div className="flex justify-start">
                      <div className="max-w-[85%] bg-card border border-border rounded-xl rounded-bl-sm px-4 py-3">
                        <div className="flex items-center gap-2 mb-2">
                          <div className="w-5 h-5 rounded bg-accent/20 flex items-center justify-center">
                            <HiOutlineShieldCheck className="h-3 w-3 text-[hsl(213,32%,52%)]" />
                          </div>
                          <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">EDQ Knowledge Agent</span>
                        </div>
                        <div className="space-y-2">
                          <Skeleton className="h-4 w-full" />
                          <Skeleton className="h-4 w-5/6" />
                          <Skeleton className="h-4 w-4/6" />
                        </div>
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>
              </ScrollArea>

              {/* Chat Error */}
              {chatError && (
                <div className="px-6">
                  <div className="max-w-3xl mx-auto mb-2 flex items-center gap-2 px-3 py-2 rounded-lg bg-destructive/10 text-destructive text-xs">
                    <HiOutlineExclamationCircle className="h-4 w-4 flex-shrink-0" />
                    <span>{chatError}</span>
                  </div>
                </div>
              )}

              {/* Chat Input */}
              <div className="px-6 py-4 border-t border-border bg-card/30">
                <div className="max-w-3xl mx-auto flex gap-2">
                  <Input
                    placeholder="Ask a question about EDQ..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSendChat() } }}
                    disabled={chatLoading}
                    className="flex-1 bg-card border-border"
                  />
                  <Button onClick={() => handleSendChat()} disabled={chatLoading || !chatInput.trim()} className="gap-2">
                    {chatLoading ? (
                      <span className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                    ) : (
                      <HiOutlinePaperAirplane className="h-4 w-4 rotate-90" />
                    )}
                    <span>Ask EDQ</span>
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* ========== RESULT ANALYZER ========== */}
          {activeTab === 'analyzer' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Header */}
              <div className="px-6 py-4 border-b border-border bg-card/50">
                <h2 className="text-lg font-semibold">Result Analyzer</h2>
                <p className="text-xs text-muted-foreground">Classify finding severity, get remediation steps, and generate override templates</p>
              </div>

              <div className="flex-1 flex overflow-hidden">
                {/* Left Column: Input */}
                <div className="w-[40%] border-r border-border overflow-y-auto p-6">
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <HiOutlineSearch className="h-4 w-4 text-[hsl(213,32%,52%)]" />
                        Finding Input
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Test Category</Label>
                        <Select
                          value={analyzerForm.testCategory}
                          onValueChange={(val) => setAnalyzerForm(prev => ({ ...prev, testCategory: val }))}
                        >
                          <SelectTrigger className="bg-card border-border">
                            <SelectValue placeholder="Select category..." />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Port Scan">Port Scan</SelectItem>
                            <SelectItem value="TLS/SSL">TLS/SSL</SelectItem>
                            <SelectItem value="SSH">SSH</SelectItem>
                            <SelectItem value="BACnet">BACnet</SelectItem>
                            <SelectItem value="Credentials">Credentials</SelectItem>
                            <SelectItem value="Other">Other</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Device Type</Label>
                        <Select
                          value={analyzerForm.deviceType}
                          onValueChange={(val) => setAnalyzerForm(prev => ({ ...prev, deviceType: val }))}
                        >
                          <SelectTrigger className="bg-card border-border">
                            <SelectValue placeholder="Select device..." />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Pelco">Pelco</SelectItem>
                            <SelectItem value="EasyIO">EasyIO</SelectItem>
                            <SelectItem value="Other">Other</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <Label className="text-xs text-muted-foreground">Finding Details *</Label>
                          <span className={cn('text-[10px]', (analyzerForm.findingDetails.length > 1800) ? 'text-destructive' : 'text-muted-foreground')}>
                            {analyzerForm.findingDetails.length}/2000
                          </span>
                        </div>
                        <Textarea
                          placeholder="Paste raw test output or describe finding..."
                          value={analyzerForm.findingDetails}
                          onChange={(e) => {
                            if (e.target.value.length <= 2000) {
                              setAnalyzerForm(prev => ({ ...prev, findingDetails: e.target.value }))
                            }
                          }}
                          rows={8}
                          className="bg-card border-border resize-none"
                        />
                      </div>

                      <Button
                        onClick={handleAnalyze}
                        disabled={analyzerLoading || !analyzerForm.findingDetails.trim()}
                        className="w-full gap-2"
                      >
                        {analyzerLoading ? (
                          <span className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                        ) : (
                          <HiOutlineSearch className="h-4 w-4" />
                        )}
                        <span>{analyzerLoading ? 'Analyzing...' : 'Analyze Finding'}</span>
                      </Button>

                      {analyzerError && (
                        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-destructive/10 text-destructive text-xs">
                          <HiOutlineExclamationCircle className="h-4 w-4 flex-shrink-0" />
                          <span>{analyzerError}</span>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Analysis History */}
                  {analyzerHistory.length > 0 && (
                    <div className="mt-4">
                      <Collapsible open={historyOpen} onOpenChange={setHistoryOpen}>
                        <CollapsibleTrigger asChild>
                          <button className="w-full flex items-center justify-between px-3 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors">
                            <span>Previous Analyses ({analyzerHistory.length})</span>
                            {historyOpen ? <HiOutlineChevronUp className="h-3.5 w-3.5" /> : <HiOutlineChevronDown className="h-3.5 w-3.5" />}
                          </button>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                          <div className="space-y-2 mt-2">
                            {analyzerHistory.map((item, idx) => (
                              <button
                                key={idx}
                                onClick={() => setAnalyzerResult(item)}
                                className="w-full text-left px-3 py-2 rounded-lg bg-card border border-border hover:border-[hsl(213,32%,52%)] transition-colors"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-foreground">{item.input_summary}</span>
                                  <SeverityBadge severity={item.severity} />
                                </div>
                                <span className="text-[10px] text-muted-foreground">{item.timestamp}</span>
                              </button>
                            ))}
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    </div>
                  )}
                </div>

                {/* Right Column: Results */}
                <div className="w-[60%] overflow-y-auto p-6">
                  {analyzerLoading && (
                    <div className="space-y-6">
                      <div className="space-y-3">
                        <Skeleton className="h-8 w-24" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-5/6" />
                      </div>
                      <Separator />
                      <div className="space-y-3">
                        <Skeleton className="h-5 w-48" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-4/5" />
                      </div>
                      <Separator />
                      <div className="space-y-3">
                        <Skeleton className="h-5 w-48" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-5/6" />
                      </div>
                    </div>
                  )}

                  {!analyzerLoading && !displayedAnalysis && (
                    <div className="flex flex-col items-center justify-center h-full space-y-4">
                      <div className="w-16 h-16 rounded-2xl bg-accent/10 flex items-center justify-center">
                        <HiOutlineShieldCheck className="h-8 w-8 text-muted-foreground" />
                      </div>
                      <div className="text-center space-y-1">
                        <h3 className="text-sm font-medium text-foreground">Paste a finding to get started</h3>
                        <p className="text-xs text-muted-foreground max-w-xs">Enter your test output or finding description on the left, and the analyzer will classify severity and provide remediation steps.</p>
                      </div>
                    </div>
                  )}

                  {!analyzerLoading && displayedAnalysis && (
                    <div className="space-y-6">
                      {/* Severity */}
                      <div className="space-y-2">
                        <div className="flex items-center gap-3">
                          <SeverityBadge severity={displayedAnalysis.severity} />
                          <span className="text-xs text-muted-foreground">Severity Classification</span>
                        </div>
                        {displayedAnalysis.severity_rationale && (
                          <p className="text-sm text-muted-foreground leading-relaxed">{displayedAnalysis.severity_rationale}</p>
                        )}
                      </div>

                      <Separator />

                      {/* Remediation */}
                      {displayedAnalysis.remediation && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <h3 className="text-sm font-semibold">Remediation Recommendation</h3>
                            <CopyButton text={displayedAnalysis.remediation} label="Copy" />
                          </div>
                          <div className="rounded-lg bg-card border border-border p-4">
                            {renderMarkdown(displayedAnalysis.remediation)}
                          </div>
                        </div>
                      )}

                      <Separator />

                      {/* Override Justification */}
                      {displayedAnalysis.override_justification && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <h3 className="text-sm font-semibold">Override Justification Template</h3>
                            <CopyButton text={displayedAnalysis.override_justification} label="Copy" />
                          </div>
                          <div className="rounded-lg bg-card border border-border p-4">
                            {renderMarkdown(displayedAnalysis.override_justification)}
                          </div>
                        </div>
                      )}

                      <Separator />

                      {/* Related Tests */}
                      {displayedAnalysis.related_tests && (
                        <div className="space-y-2">
                          <h3 className="text-sm font-semibold">Related Tests</h3>
                          <div className="flex flex-wrap gap-2">
                            {displayedAnalysis.related_tests.split(',').map((test, idx) => (
                              <Badge key={idx} variant="secondary" className="text-xs">
                                {test.trim()}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      <Separator />

                      {/* Additional Context */}
                      {displayedAnalysis.additional_context && (
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <h3 className="text-sm font-semibold">Additional Context</h3>
                            <CopyButton text={displayedAnalysis.additional_context} label="Copy" />
                          </div>
                          <div className="rounded-lg bg-muted/30 border border-border p-4">
                            {renderMarkdown(displayedAnalysis.additional_context)}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ========== REPORT DRAFTOR ========== */}
          {activeTab === 'report' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Header */}
              <div className="px-6 py-4 border-b border-border bg-card/50">
                <h2 className="text-lg font-semibold">Report Draftor</h2>
                <p className="text-xs text-muted-foreground">Generate executive summaries and detailed technical narratives for EDQ reports</p>
              </div>

              <div className="flex-1 flex overflow-hidden">
                {/* Left Column: Input */}
                <div className="w-[40%] border-r border-border overflow-y-auto p-6">
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-sm font-semibold flex items-center gap-2">
                        <HiOutlineDocumentText className="h-4 w-4 text-[hsl(213,32%,52%)]" />
                        Device Details
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Device Name</Label>
                        <Input
                          placeholder="e.g., Pelco Sarix IX30DN-E"
                          value={reportForm.deviceName}
                          onChange={(e) => setReportForm(prev => ({ ...prev, deviceName: e.target.value }))}
                          className="bg-card border-border"
                        />
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">IP Address</Label>
                        <Input
                          placeholder="e.g., 192.168.1.100"
                          value={reportForm.ipAddress}
                          onChange={(e) => setReportForm(prev => ({ ...prev, ipAddress: e.target.value }))}
                          className="bg-card border-border"
                        />
                        <p className="text-[10px] text-muted-foreground">Format: xxx.xxx.xxx.xxx</p>
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Manufacturer</Label>
                        <Select
                          value={reportForm.manufacturer}
                          onValueChange={(val) => setReportForm(prev => ({ ...prev, manufacturer: val }))}
                        >
                          <SelectTrigger className="bg-card border-border">
                            <SelectValue placeholder="Select manufacturer..." />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="Pelco">Pelco</SelectItem>
                            <SelectItem value="EasyIO">EasyIO</SelectItem>
                            <SelectItem value="Other">Other</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">System Type</Label>
                        <Input
                          placeholder="e.g., IP Camera, HVAC Controller"
                          value={reportForm.systemType}
                          onChange={(e) => setReportForm(prev => ({ ...prev, systemType: e.target.value }))}
                          className="bg-card border-border"
                        />
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Overall Result</Label>
                        <div className="flex gap-2">
                          {['Pass', 'Fail', 'Conditional Pass'].map((opt) => (
                            <button
                              key={opt}
                              onClick={() => setReportForm(prev => ({ ...prev, overallResult: opt }))}
                              className={cn(
                                'flex-1 px-3 py-2 rounded-md text-xs font-medium border transition-all duration-200',
                                reportForm.overallResult === opt
                                  ? opt === 'Pass'
                                    ? 'bg-green-900/40 border-green-700/50 text-green-300'
                                    : opt === 'Fail'
                                    ? 'bg-red-900/40 border-red-700/50 text-red-300'
                                    : 'bg-yellow-900/40 border-yellow-700/50 text-yellow-300'
                                  : 'bg-card border-border text-muted-foreground hover:text-foreground hover:border-[hsl(213,32%,52%)]'
                              )}
                            >
                              {opt}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <Label className="text-xs text-muted-foreground">Key Findings Summary</Label>
                          <span className={cn('text-[10px]', (reportForm.keyFindings.length > 1800) ? 'text-destructive' : 'text-muted-foreground')}>
                            {reportForm.keyFindings.length}/2000
                          </span>
                        </div>
                        <Textarea
                          placeholder="Summarize key test findings, vulnerabilities, and notable observations..."
                          value={reportForm.keyFindings}
                          onChange={(e) => {
                            if (e.target.value.length <= 2000) {
                              setReportForm(prev => ({ ...prev, keyFindings: e.target.value }))
                            }
                          }}
                          rows={5}
                          className="bg-card border-border resize-none"
                        />
                      </div>

                      <div className="space-y-1.5">
                        <Label className="text-xs text-muted-foreground">Audience</Label>
                        <div className="flex gap-2">
                          {['Technical', 'Executive'].map((opt) => (
                            <button
                              key={opt}
                              onClick={() => setReportForm(prev => ({ ...prev, audience: opt }))}
                              className={cn(
                                'flex-1 px-3 py-2 rounded-md text-xs font-medium border transition-all duration-200',
                                reportForm.audience === opt
                                  ? 'bg-[hsl(213,32%,52%)] border-[hsl(213,32%,52%)] text-white'
                                  : 'bg-card border-border text-muted-foreground hover:text-foreground hover:border-[hsl(213,32%,52%)]'
                              )}
                            >
                              {opt}
                            </button>
                          ))}
                        </div>
                      </div>

                      <Button
                        onClick={handleGenerateReport}
                        disabled={reportLoading || (!reportForm.deviceName.trim() && !reportForm.keyFindings.trim())}
                        className="w-full gap-2"
                      >
                        {reportLoading ? (
                          <span className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                        ) : (
                          <HiOutlineLightningBolt className="h-4 w-4" />
                        )}
                        <span>{reportLoading ? 'Generating...' : 'Generate Narrative'}</span>
                      </Button>

                      {reportError && (
                        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-destructive/10 text-destructive text-xs">
                          <HiOutlineExclamationCircle className="h-4 w-4 flex-shrink-0" />
                          <span>{reportError}</span>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>

                {/* Right Column: Output */}
                <div className="w-[60%] overflow-y-auto p-6">
                  {reportLoading && (
                    <div className="space-y-6">
                      <div className="space-y-3">
                        <Skeleton className="h-8 w-48" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-5/6" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-4/5" />
                      </div>
                      <Separator />
                      <div className="space-y-3">
                        <Skeleton className="h-8 w-48" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-5/6" />
                      </div>
                    </div>
                  )}

                  {!reportLoading && !displayedReport && (
                    <div className="flex flex-col items-center justify-center h-full space-y-4">
                      <div className="w-16 h-16 rounded-2xl bg-accent/10 flex items-center justify-center">
                        <HiOutlineDocumentText className="h-8 w-8 text-muted-foreground" />
                      </div>
                      <div className="text-center space-y-1">
                        <h3 className="text-sm font-medium text-foreground">Fill in device details and generate a narrative</h3>
                        <p className="text-xs text-muted-foreground max-w-xs">Provide the device information and key findings on the left, then generate a professional EDQ report narrative.</p>
                      </div>
                    </div>
                  )}

                  {!reportLoading && displayedReport && (
                    <div className="space-y-4">
                      <Tabs value={reportTab} onValueChange={setReportTab}>
                        <div className="flex items-center justify-between">
                          <TabsList className="bg-muted">
                            <TabsTrigger value="executive" className="text-xs">Executive Summary</TabsTrigger>
                            <TabsTrigger value="detailed" className="text-xs">Detailed Narrative</TabsTrigger>
                            {(reportForm.overallResult === 'Conditional Pass' || displayedReport.conditions) && (
                              <TabsTrigger value="conditions" className="text-xs">Conditions</TabsTrigger>
                            )}
                          </TabsList>
                        </div>

                        <TabsContent value="executive" className="mt-4">
                          <Card className="bg-card border-border">
                            <CardHeader className="pb-2 flex flex-row items-center justify-between">
                              <CardTitle className="text-sm">Executive Summary</CardTitle>
                              <div className="flex gap-1">
                                <CopyButton text={displayedReport.executive_summary} label="Copy" />
                                <Button variant="ghost" size="sm" onClick={handleGenerateReport} disabled={reportLoading} className="h-7 gap-1.5 text-xs text-muted-foreground hover:text-foreground">
                                  <HiOutlineRefresh className="h-3.5 w-3.5" />
                                  <span>Regenerate</span>
                                </Button>
                              </div>
                            </CardHeader>
                            <CardContent>
                              {displayedReport.executive_summary ? renderMarkdown(displayedReport.executive_summary) : (
                                <p className="text-sm text-muted-foreground">No executive summary generated.</p>
                              )}
                            </CardContent>
                          </Card>
                        </TabsContent>

                        <TabsContent value="detailed" className="mt-4">
                          <Card className="bg-card border-border">
                            <CardHeader className="pb-2 flex flex-row items-center justify-between">
                              <CardTitle className="text-sm">Detailed Narrative</CardTitle>
                              <div className="flex gap-1">
                                <CopyButton text={displayedReport.detailed_narrative} label="Copy" />
                                <Button variant="ghost" size="sm" onClick={handleGenerateReport} disabled={reportLoading} className="h-7 gap-1.5 text-xs text-muted-foreground hover:text-foreground">
                                  <HiOutlineRefresh className="h-3.5 w-3.5" />
                                  <span>Regenerate</span>
                                </Button>
                              </div>
                            </CardHeader>
                            <CardContent>
                              {displayedReport.detailed_narrative ? renderMarkdown(displayedReport.detailed_narrative) : (
                                <p className="text-sm text-muted-foreground">No detailed narrative generated.</p>
                              )}
                            </CardContent>
                          </Card>
                        </TabsContent>

                        <TabsContent value="conditions" className="mt-4">
                          <Card className="bg-card border-border">
                            <CardHeader className="pb-2 flex flex-row items-center justify-between">
                              <CardTitle className="text-sm">Conditions</CardTitle>
                              <div className="flex gap-1">
                                <CopyButton text={displayedReport.conditions} label="Copy" />
                              </div>
                            </CardHeader>
                            <CardContent>
                              {displayedReport.conditions ? renderMarkdown(displayedReport.conditions) : (
                                <p className="text-sm text-muted-foreground">No conditions specified.</p>
                              )}
                            </CardContent>
                          </Card>
                        </TabsContent>
                      </Tabs>

                      {/* Word count */}
                      {displayedReport.word_count && (
                        <div className="flex justify-end">
                          <span className="text-[10px] text-muted-foreground">Approx. {displayedReport.word_count} words</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </ErrorBoundary>
  )
}
