import { Redirect } from 'expo-router';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

const rows = [
  { time: '14:02:11', event: 'Key rotation initiated', risk: 'Low' },
  { time: '13:45:00', event: 'Failed auth attempt (root)', risk: 'Med' },
  { time: '13:12:44', event: 'Policy violation detect', risk: 'High', high: true },
  { time: '12:30:19', event: 'Node sync complete', risk: 'Low' },
  { time: '11:15:02', event: 'DB Backup successful', risk: 'Low' },
  { time: '10:05:55', event: 'Config updated (admin)', risk: 'Med' },
];

export default function AdminAuditLogsScreen() {
  const { hasPermission } = useSession();

  if (!hasPermission('admin:audit:read')) {
    return <Redirect href="/admin/login" />;
  }

  return (
    <View style={styles.root}>
      <View style={styles.topBar}>
        <Text style={styles.pageTitle}>System Audit Logs</Text>
        <Text style={styles.live}>Live monitoring active. Last 24 hours.</Text>
      </View>

      <View style={styles.toolbar}>
        <View style={styles.searchWrap}><Text style={styles.searchText}>Search by IP, Event, or User...</Text></View>
        <View style={styles.pills}><Pill label="ALL" active /><Pill label="LOW" /><Pill label="MED" /><Pill label="HIGH" danger /></View>
      </View>

      <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        <View style={styles.tableCard}>
          <View style={styles.tableHeader}>
            <Text style={styles.headTime}>Timestamp (UTC)</Text>
            <Text style={styles.headEvent}>Event Details</Text>
            <Text style={styles.headActor}>User / Actor</Text>
            <Text style={styles.headIp}>Source IP</Text>
            <Text style={styles.headRisk}>Risk</Text>
          </View>
          {rows.map((row) => (
            <View key={`${row.time}-${row.event}`} style={[styles.tableRow, row.high && styles.highRow]}>
              <Text style={[styles.cellTime, row.high && styles.highText]}>{row.time}</Text>
              <View style={styles.eventCell}>
                <Text style={[styles.eventTitle, row.high && styles.highText]}>{row.event}</Text>
                <Text style={styles.eventSubtitle}>{row.high ? 'Auth service rejected 5 attempts for admin account.' : 'System record.'}</Text>
              </View>
              <Text style={styles.actor}>{row.high ? 'Unknown Actor' : 'Operative Alpha'}</Text>
              <Text style={styles.ip}>{row.high ? '192.168.1.105' : '172.16.0.4'}</Text>
              <Text style={[styles.risk, row.risk === 'High' && styles.riskHigh, row.risk === 'Med' && styles.riskMed]}>{row.risk}</Text>
            </View>
          ))}
        </View>
      </ScrollView>
    </View>
  );
}

function Pill({ label, active = false, danger = false }: { label: string; active?: boolean; danger?: boolean }) {
  return <View style={[styles.pill, active && styles.pillActive, danger && styles.pillDanger]}><Text style={[styles.pillText, active && styles.pillTextActive, danger && styles.pillTextDanger]}>{label}</Text></View>;
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  topBar: { height: 64, borderBottomWidth: 1, borderBottomColor: colors.border, paddingHorizontal: 16, justifyContent: 'center', gap: 4 },
  pageTitle: { color: colors.text, fontSize: 32, lineHeight: 40, fontWeight: '700' },
  live: { color: colors.muted, fontSize: 13 },
  toolbar: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, padding: 16, margin: 16, gap: 12 },
  searchWrap: { height: 40, borderBottomWidth: 1, borderBottomColor: colors.border, justifyContent: 'center' },
  searchText: { color: '#94A3B8', fontSize: 13 },
  pills: { flexDirection: 'row', gap: 8, flexWrap: 'wrap' },
  pill: { borderRadius: 999, borderWidth: 1, borderColor: colors.border, paddingHorizontal: 12, paddingVertical: 6, backgroundColor: colors.background },
  pillActive: { backgroundColor: colors.surface },
  pillDanger: { borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)' },
  pillText: { color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  pillTextActive: { color: colors.text },
  pillTextDanger: { color: '#ef4444' },
  content: { paddingHorizontal: 16, paddingBottom: 16 },
  tableCard: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, overflow: 'hidden' },
  tableHeader: { flexDirection: 'row', paddingHorizontal: 16, paddingVertical: 12, backgroundColor: colors.background, borderBottomWidth: 1, borderBottomColor: colors.border },
  headTime: { width: 120, color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  headEvent: { flex: 1, color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  headActor: { width: 140, color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  headIp: { width: 120, color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  headRisk: { width: 80, color: colors.muted, fontSize: 12, fontFamily: 'monospace', textAlign: 'center' },
  tableRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: colors.border },
  highRow: { backgroundColor: 'rgba(239,68,68,0.05)' },
  cellTime: { width: 120, color: colors.text, fontSize: 12, fontFamily: 'monospace', opacity: 0.8 },
  eventCell: { flex: 1, paddingRight: 12 },
  eventTitle: { color: colors.text, fontWeight: '700' },
  eventSubtitle: { color: colors.muted, fontSize: 12, marginTop: 2 },
  actor: { width: 140, color: colors.text },
  ip: { width: 120, color: colors.text, fontFamily: 'monospace' },
  risk: { width: 80, color: '#10B981', textAlign: 'center', fontSize: 10, fontFamily: 'monospace', textTransform: 'uppercase', fontWeight: '700' },
  riskMed: { color: '#F59E0B' },
  riskHigh: { color: '#EF4444' },
  highText: { color: '#EF4444' },
});
