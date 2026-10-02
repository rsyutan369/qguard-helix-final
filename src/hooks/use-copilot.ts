import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/contexts/auth-context';
import type {
  CopilotAnswer,
  CopilotContext,
  CopilotConversation,
  CopilotInsight,
  CopilotMessage,
  CopilotStage,
  CopilotStreamEvent,
  CopilotSuggestion,
  CopilotToolRun,
} from '@/types/copilot';

/**
 * useCopilot — client for Sophia, the QGuard Helix AI Security Copilot™.
 *
 * Drives the floating dock and the full console: tenant/RBAC context,
 * suggestions, proactive insights, conversation history, and a POST-based SSE
 * chat stream (token in the Authorization header, never a URL) that surfaces
 * the reasoning stages, live tool runs and the final structured answer.
 */

export type CopilotLoadState = 'idle' | 'loading' | 'success' | 'error';

export interface StreamingState {
  active: boolean;
  stage: CopilotStage | null;
  stageLabel: string;
  toolRuns: CopilotToolRun[];
}

const IDLE_STREAM: StreamingState = { active: false, stage: null, stageLabel: '', toolRuns: [] };

export function useCopilot(currentPage?: string) {
  const { session } = useAuth();
  const token = session?.access_token;

  const [context, setContext] = useState<CopilotContext | null>(null);
  const [suggestions, setSuggestions] = useState<CopilotSuggestion[]>([]);
  const [insights, setInsights] = useState<CopilotInsight[]>([]);
  const [insightsState, setInsightsState] = useState<CopilotLoadState>('idle');
  const [conversations, setConversations] = useState<CopilotConversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [streaming, setStreaming] = useState<StreamingState>(IDLE_STREAM);
  const [error, setError] = useState<string | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const authHeaders = useCallback((): HeadersInit => ({
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  }), [token]);

  /* ---- Context ---------------------------------------------------- */
  const loadContext = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/v1/copilot/context', { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) setContext(payload.data || null);
    } catch { /* non-fatal */ }
  }, [token, authHeaders]);

  /* ---- Suggestions ------------------------------------------------ */
  const loadSuggestions = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch(`/api/v1/copilot/suggestions?page=${encodeURIComponent(currentPage || '')}`, { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) setSuggestions(payload.data?.suggestions || []);
    } catch { /* non-fatal */ }
  }, [token, authHeaders, currentPage]);

  /* ---- Insights --------------------------------------------------- */
  const loadInsights = useCallback(async () => {
    if (!token) return;
    setInsightsState('loading');
    try {
      const res = await fetch('/api/v1/copilot/insights', { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload?.error?.message || `HTTP ${res.status}`);
      setInsights(payload.data?.insights || []);
      setInsightsState('success');
    } catch {
      setInsightsState('error');
    }
  }, [token, authHeaders]);

  /* ---- Conversations ---------------------------------------------- */
  const loadConversations = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/v1/copilot/conversations', { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) setConversations(payload.data?.conversations || []);
    } catch { /* non-fatal */ }
  }, [token, authHeaders]);

  const openConversation = useCallback(async (id: string) => {
    if (!token) return;
    setActiveConversationId(id);
    try {
      const res = await fetch(`/api/v1/copilot/conversations/${id}`, { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      if (res.ok) setMessages(payload.data?.messages || []);
    } catch { /* non-fatal */ }
  }, [token, authHeaders]);

  const newConversation = useCallback(() => {
    setActiveConversationId(null);
    setMessages([]);
    setStreaming(IDLE_STREAM);
    setError(null);
  }, []);

  const pinConversation = useCallback(async (id: string, pinned: boolean) => {
    if (!token) return;
    try {
      await fetch(`/api/v1/copilot/conversations/${id}`, { method: 'PATCH', headers: authHeaders(), body: JSON.stringify({ pinned }) });
      setConversations((prev) => prev.map((c) => (c.id === id ? { ...c, pinned } : c)));
    } catch { /* non-fatal */ }
  }, [token, authHeaders]);

  const deleteConversation = useCallback(async (id: string) => {
    if (!token) return;
    try {
      await fetch(`/api/v1/copilot/conversations/${id}`, { method: 'DELETE', headers: authHeaders() });
      setConversations((prev) => prev.filter((c) => c.id !== id));
      if (activeConversationId === id) newConversation();
    } catch { /* non-fatal */ }
  }, [token, authHeaders, activeConversationId, newConversation]);

  const exportConversation = useCallback(async (id: string) => {
    if (!token) return null;
    try {
      const res = await fetch(`/api/v1/copilot/conversations/${id}/export`, { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      return res.ok ? payload.data : null;
    } catch {
      return null;
    }
  }, [token, authHeaders]);

  const searchConversations = useCallback(async (q: string) => {
    if (!token || !q.trim()) return [];
    try {
      const res = await fetch(`/api/v1/copilot/conversations/search?q=${encodeURIComponent(q)}`, { headers: authHeaders() });
      const payload = await res.json().catch(() => ({}));
      return res.ok ? (payload.data?.results || []) : [];
    } catch {
      return [];
    }
  }, [token, authHeaders]);

  /* ---- Chat (POST SSE stream) ------------------------------------- */
  const sendMessage = useCallback(async (message: string) => {
    if (!token || !message.trim() || streaming.active) return;
    setError(null);

    // Optimistic user bubble.
    const userMessage: CopilotMessage = {
      id: `local-${Date.now()}`,
      conversationId: activeConversationId || 'pending',
      role: 'user',
      content: message.trim(),
      createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMessage]);
    setStreaming({ active: true, stage: 'thinking', stageLabel: 'Sophia is thinking…', toolRuns: [] });

    const controller = new AbortController();
    abortRef.current = controller;

    let finalAnswer: CopilotAnswer | null = null;
    let conversationId = activeConversationId;

    const handleEvent = (event: CopilotStreamEvent & { conversationId?: string }) => {
      switch (event.type) {
        case 'stage':
          setStreaming((prev) => ({ ...prev, active: true, stage: event.stage, stageLabel: event.label }));
          break;
        case 'tool':
          setStreaming((prev) => ({ ...prev, toolRuns: [...prev.toolRuns, event.run] }));
          break;
        case 'answer':
          finalAnswer = event.answer;
          break;
        case 'error':
          setError(event.message);
          break;
        default:
          break;
      }
    };

    try {
      const res = await fetch('/api/v1/copilot/chat?stream=1', {
        method: 'POST',
        headers: { ...authHeaders(), Accept: 'text/event-stream' },
        body: JSON.stringify({ message: message.trim(), conversationId: activeConversationId, page: currentPage }),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        const payload = await res.json().catch(() => ({}));
        throw new Error(payload?.error?.message || `HTTP ${res.status}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const consumeFrame = (frame: string) => {
        const dataLines: string[] = [];
        for (const line of frame.split('\n')) {
          if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''));
        }
        if (!dataLines.length) return;
        try {
          const parsed = JSON.parse(dataLines.join('\n'));
          if (parsed?.type === 'meta' && parsed.conversationId) conversationId = parsed.conversationId;
          else handleEvent(parsed);
        } catch { /* ignore malformed frame */ }
      };
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let boundary = buffer.indexOf('\n\n');
        while (boundary !== -1) {
          consumeFrame(buffer.slice(0, boundary));
          buffer = buffer.slice(boundary + 2);
          boundary = buffer.indexOf('\n\n');
        }
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        setError((err as Error)?.message || 'Sophia could not answer.');
      }
    } finally {
      if (finalAnswer) {
        const assistantMessage: CopilotMessage = {
          id: (finalAnswer as CopilotAnswer).id,
          conversationId: conversationId || 'pending',
          role: 'assistant',
          content: (finalAnswer as CopilotAnswer).summary,
          answer: finalAnswer,
          createdAt: (finalAnswer as CopilotAnswer).generatedAt,
        };
        setMessages((prev) => [...prev, assistantMessage]);
      }
      if (conversationId && conversationId !== activeConversationId) {
        setActiveConversationId(conversationId);
        void loadConversations();
      } else {
        void loadConversations();
      }
      setStreaming(IDLE_STREAM);
      abortRef.current = null;
    }
  }, [token, authHeaders, activeConversationId, currentPage, streaming.active, loadConversations]);

  const stopStreaming = useCallback(() => {
    abortRef.current?.abort();
    setStreaming(IDLE_STREAM);
  }, []);

  /* ---- Feedback — rate an answer (recorded to the tenant audit trail) ---- */
  const sendFeedback = useCallback(async (answer: CopilotAnswer, rating: 'up' | 'down') => {
    if (!token) return;
    try {
      await fetch('/api/v1/copilot/feedback', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ answerId: answer.id, conversationId: activeConversationId, rating, focus: answer.focus }),
      });
    } catch { /* feedback is best-effort and never blocks the chat */ }
  }, [token, authHeaders, activeConversationId]);

  /* ---- Bootstrap -------------------------------------------------- */
  useEffect(() => {
    if (!token) return;
    void loadContext();
    void loadConversations();
  }, [token, loadContext, loadConversations]);

  useEffect(() => {
    void loadSuggestions();
  }, [loadSuggestions]);

  useEffect(() => () => abortRef.current?.abort(), []);

  return {
    context,
    suggestions,
    insights,
    insightsState,
    conversations,
    activeConversationId,
    messages,
    streaming,
    error,
    // actions
    sendMessage,
    stopStreaming,
    sendFeedback,
    loadInsights,
    loadConversations,
    openConversation,
    newConversation,
    pinConversation,
    deleteConversation,
    exportConversation,
    searchConversations,
    refreshContext: loadContext,
  };
}
