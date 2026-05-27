import { Feather, MaterialIcons } from '@expo/vector-icons';
import { Redirect } from 'expo-router';
import { Link } from 'expo-router';
import { Image, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

const cards = [
  { label: 'Active Users', value: '12,409', detail: '+4.2% from last week', icon: 'group', tone: '#0284C7' },
  { label: 'Encrypted Msgs (24h)', value: '1.8M', detail: 'End-to-end secured', icon: 'enhanced-encryption', tone: '#0284C7' },
  { label: 'System Uptime', value: '99.99%', detail: 'All services operational', icon: 'dns', tone: '#10B981' },
  { label: 'Active Alerts', value: '3', detail: 'Require immediate attention', icon: 'warning', tone: '#EF4444' },
];

const rows = [
  { time: '14:02:11', event: 'Key rotation initiated', risk: 'Low' },
  { time: '13:45:00', event: 'Failed auth attempt (root)', risk: 'Med' },
  { time: '13:12:44', event: 'Policy violation detect', risk: 'High', high: true },
  { time: '12:30:19', event: 'Node sync complete', risk: 'Low' },
  { time: '11:15:02', event: 'DB Backup successful', risk: 'Low' },
  { time: '10:05:55', event: 'Config updated (admin)', risk: 'Med' },
];

export default function AdminDashboardScreen() {
  const { signOut, hasPermission } = useSession();

  if (!hasPermission('admin:dashboard:read')) {
    return <Redirect href="/admin/login" />;
  }

  return (
    <View style={styles.root}>
      <View style={styles.sidebar}>
        <View style={styles.brandRow}>
          <View style={styles.brandIcon}><MaterialIcons name="security" size={18} color={colors.text} /></View>
          <View>
            <Text style={styles.brand}>Cipher Admin</Text>
            <Text style={styles.brandSub}>Secure Enterprise Node</Text>
          </View>
        </View>
        <NavItem icon="dashboard" label="Dashboard" />
        <NavItem icon="group" label="Users" />
        <NavItem icon="receipt-long" label="Audit Logs" active />
        <NavItem icon="verified-user" label="Security Settings" />
        <View style={styles.sidebarFooter}>
          <NavItem icon="help" label="Support" />
          <Pressable style={({ pressed }) => [styles.navItem, styles.navDanger, pressed && styles.pressed]} onPress={signOut}>
            <MaterialIcons name="logout" size={18} color="#EF4444" />
            <Text style={styles.navTextDanger}>Sign Out</Text>
          </Pressable>
        </View>
      </View>

      <View style={styles.main}>
        <View style={styles.topBar}>
          <Text style={styles.topTitle}>Admin Console</Text>
          <View style={styles.searchWrap}><Feather name="search" size={16} color="#94A3B8" /><Text style={styles.searchText}>Search users, IDs, or IPs...</Text></View>
          <View style={styles.topActions}><Feather name="bell" size={18} color="#94A3B8" /><Feather name="settings" size={18} color="#94A3B8" /></View>
        </View>

        <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
          <View style={styles.hero}>
            <Text style={styles.title}>Dashboard Overview</Text>
            <Text style={styles.subtitle}>Real-time system metrics and security posture.</Text>
            <Pressable style={styles.exportButton}><MaterialIcons name="download" size={18} color={colors.text} /><Text style={styles.exportText}>Export Report</Text></Pressable>
          </View>

          <View style={styles.cardGrid}>
            {cards.map((card) => (
              <View key={card.label} style={styles.card}>
                <View style={styles.cardTop}><Text style={styles.cardLabel}>{card.label}</Text><MaterialIcons name={card.icon as never} size={18} color={card.tone} /></View>
                <Text style={styles.cardValue}>{card.value}</Text>
                <Text style={styles.cardDetail}>{card.detail}</Text>
              </View>
            ))}
          </View>

          <View style={styles.panelsRow}>
            <View style={[styles.panel, styles.mapPanel]}>
              <View style={styles.panelHeader}>
                <Text style={styles.panelTitle}><MaterialIcons name="public" size={18} color={colors.accentSoft} /> Active Sessions Node Activity</Text>
                <View style={styles.liveWrap}><View style={styles.liveDot} /><Text style={styles.liveText}>Live</Text></View>
              </View>
              <View style={styles.mapCanvas}><Text style={styles.mapText}>[Geospatial Render Engine Initializing]</Text></View>
            </View>
            <View style={[styles.panel, styles.logsPanel]}>
              <Text style={styles.panelTitle}>Recent Audit Logs</Text>
              <View style={styles.logList}>
                {rows.map((row) => (
                  <View key={`${row.time}-${row.event}`} style={[styles.logRow, row.high && styles.logHigh]}>
                    <Text style={styles.logTime}>{row.time}</Text>
                    <Text style={styles.logEvent}>{row.event}</Text>
                    <Text style={[styles.logRisk, row.risk === 'High' && styles.riskHigh, row.risk === 'Med' && styles.riskMed]}>{row.risk}</Text>
                  </View>
                ))}
              </View>
            </View>
          </View>
        </ScrollView>
      </View>
    </View>
  );
}

function NavItem({ icon, label, active = false, danger = false }: { icon: keyof typeof MaterialIcons.glyphMap; label: string; active?: boolean; danger?: boolean }) {
  return <View style={[styles.navItem, active && styles.navActive, danger && styles.navDanger]}><MaterialIcons name={icon} size={18} color={active ? colors.text : danger ? '#EF4444' : '#94A3B8'} /><Text style={[styles.navText, active && styles.navTextActive, danger && styles.navTextDanger]}>{label}</Text></View>;
}

const styles = StyleSheet.create({
  root: { flex: 1, flexDirection: 'row', backgroundColor: colors.background },
  sidebar: { width: 256, backgroundColor: '#0e0e10', borderRightWidth: 1, borderRightColor: colors.border, padding: 16, gap: 8 },
  brandRow: { flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 12 },
  brandIcon: { width: 32, height: 32, borderRadius: 6, backgroundColor: colors.accent, alignItems: 'center', justifyContent: 'center' },
  brand: { color: colors.text, fontSize: 18, fontWeight: '900' },
  brandSub: { color: colors.muted, fontSize: 12, fontFamily: 'monospace' },
  sidebarFooter: { marginTop: 'auto', gap: 8, paddingTop: 12, borderTopWidth: 1, borderTopColor: colors.border },
  navItem: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingHorizontal: 12, paddingVertical: 10, borderRadius: 6 },
  navActive: { backgroundColor: 'rgba(2,132,199,0.12)' },
  navDanger: { marginTop: 2 },
  navText: { color: '#94A3B8' },
  navTextActive: { color: colors.text, fontWeight: '700' },
  navTextDanger: { color: '#EF4444' },
  pressed: { opacity: 0.86 },
  main: { flex: 1, minWidth: 0 },
  topBar: { height: 64, borderBottomWidth: 1, borderBottomColor: colors.border, flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, gap: 16 },
  topTitle: { color: colors.text, fontWeight: '800', fontSize: 18, flex: 0 },
  searchWrap: { flex: 1, maxWidth: 420, height: 40, borderBottomWidth: 1, borderBottomColor: colors.border, flexDirection: 'row', alignItems: 'center', gap: 8, paddingHorizontal: 2 },
  searchText: { color: '#94A3B8', fontSize: 13 },
  topActions: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  content: { padding: 16, gap: 24 },
  hero: { borderBottomWidth: 1, borderBottomColor: colors.border, paddingBottom: 16, gap: 8 },
  title: { color: colors.text, fontSize: 32, lineHeight: 40, fontWeight: '700' },
  subtitle: { color: colors.muted, fontSize: 15 },
  exportButton: { alignSelf: 'flex-start', marginTop: 8, flexDirection: 'row', alignItems: 'center', gap: 8, height: 40, paddingHorizontal: 16, borderRadius: 6, backgroundColor: colors.accent },
  exportText: { color: colors.text, fontWeight: '700' },
  cardGrid: { flexDirection: 'row', gap: 12, flexWrap: 'wrap' },
  card: { flex: 1, minWidth: 180, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, padding: 16, gap: 8 },
  cardTop: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' },
  cardLabel: { color: colors.muted, fontSize: 12, fontFamily: 'monospace', textTransform: 'uppercase' },
  cardValue: { color: colors.text, fontSize: 30, fontWeight: '700' },
  cardDetail: { color: colors.muted, fontSize: 13 },
  panelsRow: { flexDirection: 'row', gap: 12, flexWrap: 'wrap' },
  panel: { flex: 1, minWidth: 300, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, overflow: 'hidden' },
  mapPanel: { minHeight: 400 },
  logsPanel: { minHeight: 400 },
  panelHeader: { padding: 16, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.background, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  panelTitle: { color: colors.text, fontSize: 16, fontWeight: '600' },
  liveText: { color: colors.muted, fontFamily: 'monospace', fontSize: 12 },
  liveWrap: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  liveDot: { width: 8, height: 8, borderRadius: 999, backgroundColor: '#0284C7' },
  mapCanvas: { flex: 1, minHeight: 320, backgroundColor: colors.background, alignItems: 'center', justifyContent: 'center', borderRadius: 8, margin: 16, borderWidth: 1, borderColor: colors.border },
  mapText: { color: colors.muted, fontFamily: 'monospace', opacity: 0.55 },
  logList: { flex: 1 },
  logRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: colors.border, gap: 12 },
  logHigh: { backgroundColor: 'rgba(239,68,68,0.05)' },
  logTime: { width: 88, color: colors.muted, fontFamily: 'monospace', fontSize: 12 },
  logEvent: { flex: 1, color: colors.text },
  logRisk: { width: 56, textAlign: 'right', color: '#10B981', fontSize: 10, fontFamily: 'monospace', textTransform: 'uppercase', fontWeight: '700' },
  riskMed: { color: '#F59E0B' },
  riskHigh: { color: '#EF4444' },
});
