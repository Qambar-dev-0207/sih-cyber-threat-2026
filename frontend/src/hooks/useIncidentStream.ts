import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { FusedIncident, SeverityLevel } from '../types';
import { INITIAL_INCIDENTS } from '../utils/mockData';
import { useWebSocket } from './useWebSocket';

export function useIncidentStream() {
  const [incidents, setIncidents] = useState<FusedIncident[]>(INITIAL_INCIDENTS);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(INITIAL_INCIDENTS[0].incident_id);
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [threatClassFilter, setThreatClassFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [newIncidentAlert, setNewIncidentAlert] = useState<FusedIncident | null>(null);

  const pollingTimerRef = useRef<number | null>(null);

  // Helper to add or update incident
  const upsertIncident = useCallback((incoming: FusedIncident) => {
    setIncidents((prev) => {
      const idx = prev.findIndex((item) => item.incident_id === incoming.incident_id);
      if (idx >= 0) {
        const next = [...prev];
        next[idx] = { ...next[idx], ...incoming };
        return next;
      }
      // New incident -> Prepend to list
      setNewIncidentAlert(incoming);
      return [incoming, ...prev];
    });
  }, []);

  // WebSocket for /ws/incidents
  const ws = useWebSocket<FusedIncident>({
    url: '/ws/incidents',
    onMessage: (data) => {
      if (data && data.incident_id) {
        upsertIncident(data);
      }
    },
  });

  // REST fallback
  useEffect(() => {
    if (ws.status === 'CONNECTED') {
      if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
      return;
    }

    const fetchIncidents = async () => {
      try {
        const res = await fetch('/api/incidents');
        if (res.ok) {
          const data = (await res.json()) as FusedIncident[];
          if (Array.isArray(data) && data.length > 0) {
            setIncidents(data);
          }
        }
      } catch {
        // Fallback to in-memory state
      }
    };

    fetchIncidents();
    pollingTimerRef.current = window.setInterval(fetchIncidents, 3500);

    return () => {
      if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
    };
  }, [ws.status]);

  // Selected incident object
  const selectedIncident = useMemo(() => {
    if (!selectedIncidentId) return null;
    return incidents.find((inc) => inc.incident_id === selectedIncidentId) || null;
  }, [incidents, selectedIncidentId]);

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (severityFilter !== 'ALL' && inc.severity !== severityFilter) {
        return false;
      }
      if (threatClassFilter !== 'ALL' && inc.primary_threat_class !== threatClassFilter) {
        return false;
      }
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const matchId = inc.incident_id.toLowerCase().includes(q);
        const matchIp = inc.source_ip.toLowerCase().includes(q);
        const matchNarrative = inc.attack_narrative.toLowerCase().includes(q);
        const matchThreat = inc.primary_threat_class.toLowerCase().includes(q);
        const matchMitre = inc.primary_mitre_technique.toLowerCase().includes(q);
        return matchId || matchIp || matchNarrative || matchThreat || matchMitre;
      }
      return true;
    });
  }, [incidents, severityFilter, threatClassFilter, searchQuery]);

  // Count by severity
  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, ALL: incidents.length };
    incidents.forEach((inc) => {
      if (inc.severity in counts) {
        counts[inc.severity as keyof typeof counts]++;
      }
    });
    return counts;
  }, [incidents]);

  // Toggle Human Approval
  const toggleHumanApproval = useCallback((incidentId: string) => {
    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.incident_id === incidentId) {
          const nextStatus = inc.status === 'APPROVED' ? 'PENDING_REVIEW' : 'APPROVED';
          return {
            ...inc,
            status: nextStatus,
            requires_human_approval: nextStatus === 'PENDING_REVIEW',
          };
        }
        return inc;
      })
    );
  }, []);

  // Clear alert
  const clearAlert = useCallback(() => {
    setNewIncidentAlert(null);
  }, []);

  return {
    incidents,
    filteredIncidents,
    selectedIncident,
    selectedIncidentId,
    setSelectedIncidentId,
    severityFilter,
    setSeverityFilter,
    threatClassFilter,
    setThreatClassFilter,
    searchQuery,
    setSearchQuery,
    severityCounts,
    upsertIncident,
    toggleHumanApproval,
    newIncidentAlert,
    clearAlert,
    wsStatus: ws.status,
  };
}
