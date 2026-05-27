import { router } from 'expo-router';
import { Pressable, StyleSheet, Switch, Text, View } from 'react-native';

import { colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

export default function SettingsScreen() {
  const { signOut } = useSession();

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.headerTitle}>Settings</Text>
        </View>
      </View>

      <View style={styles.content}>
        <View style={styles.profileCard}>
          <View style={styles.profileAvatar}><Text style={styles.profileAvatarText}>OP</Text></View>
          <View style={styles.profileText}>
            <Text style={styles.profileName}>Operative Alpha</Text>
            <Text style={styles.profileMeta}>Secure Mode Enabled</Text>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Privacy & Security</Text>
          <View style={styles.menuCard}>
            <View style={styles.menuRow}>
              <View style={styles.menuLeft}>
                <Text style={styles.menuTitle}>Encryption Keys</Text>
                <Text style={styles.menuMeta}>Active</Text>
              </View>
              <Text style={styles.chevron}>›</Text>
            </View>
            <View style={styles.menuDivider} />
            <View style={styles.menuRow}>
              <View style={styles.menuLeft}>
                <Text style={styles.menuTitle}>Notification Privacy</Text>
                <Text style={styles.menuMeta}>Hide message content</Text>
              </View>
              <Switch value />
            </View>
            <View style={styles.menuDivider} />
            <View style={styles.menuRow}>
              <View style={styles.menuLeft}>
                <Text style={styles.menuTitle}>Self-Destruct Defaults</Text>
                <Text style={styles.menuMeta}>Off</Text>
              </View>
              <Text style={styles.chevron}>›</Text>
            </View>
          </View>
        </View>

        <View style={styles.section}>
          <Text style={[styles.sectionLabel, styles.dangerLabel]}>Danger Zone</Text>
          <View style={styles.dangerCard}>
            <Text style={styles.dangerText}>Revoking your session will immediately terminate all active connections and wipe local keys.</Text>
            <Pressable style={styles.dangerButton} onPress={() => { signOut(); router.replace('/login'); }}>
              <Text style={styles.dangerButtonText}>Revoke Session</Text>
            </Pressable>
          </View>
        </View>
      </View>

      <View style={styles.bottomNav}>
        <TabLabel label="Chats" />
        <TabLabel label="Contacts" />
        <TabLabel label="Settings" active />
      </View>
    </View>
  );
}

function TabLabel({ label, active = false }: { label: string; active?: boolean }) {
  return <View style={styles.tabItem}><Text style={[styles.tabIcon, active && styles.tabActive]}>◉</Text><Text style={[styles.tabText, active && styles.tabActive]}>{label}</Text></View>;
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  header: { height: 56, borderBottomWidth: 1, borderBottomColor: colors.border, justifyContent: 'center', paddingHorizontal: 16 },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  headerTitle: { color: colors.text, fontSize: 20, fontWeight: '700' },
  content: { flex: 1, paddingHorizontal: 16, paddingTop: 24, paddingBottom: 16, gap: 24 },
  profileCard: { flexDirection: 'row', alignItems: 'center', gap: 12, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 16, padding: 16 },
  profileAvatar: { width: 48, height: 48, borderRadius: 999, backgroundColor: colors.secondaryContainer, alignItems: 'center', justifyContent: 'center' },
  profileAvatarText: { color: colors.onSecondaryContainer, fontWeight: '700' },
  profileText: { gap: 2 },
  profileName: { color: colors.text, fontSize: 16, fontWeight: '700' },
  profileMeta: { color: colors.muted, fontSize: 12, flexDirection: 'row' },
  section: { gap: 8 },
  sectionLabel: { color: colors.outline, fontSize: 12, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: 1 },
  dangerLabel: { color: '#f87171' },
  menuCard: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 16, overflow: 'hidden' },
  menuRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', padding: 16 },
  menuLeft: { gap: 4 },
  menuTitle: { color: colors.text, fontSize: 15 },
  menuMeta: { color: colors.muted, fontSize: 13 },
  menuDivider: { height: 1, backgroundColor: colors.border },
  chevron: { color: '#64748b', fontSize: 28, lineHeight: 28 },
  dangerCard: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 16, padding: 16, gap: 12 },
  dangerText: { color: colors.muted, lineHeight: 20 },
  dangerButton: { height: 40, borderWidth: 1, borderColor: '#ef4444', borderRadius: 6, alignItems: 'center', justifyContent: 'center' },
  dangerButtonText: { color: '#ef4444', fontWeight: '700' },
  bottomNav: { height: 64, borderTopWidth: 1, borderTopColor: colors.border, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-around', backgroundColor: colors.background },
  tabItem: { alignItems: 'center', justifyContent: 'center', gap: 4 },
  tabIcon: { color: '#64748b', fontSize: 10 },
  tabText: { color: '#64748b', fontSize: 12, fontFamily: 'monospace' },
  tabActive: { color: colors.accentSoft },
});
