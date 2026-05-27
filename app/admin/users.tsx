import { Redirect } from 'expo-router';
import { Image, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { adminUsers, colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

const stats = [
  { label: 'Total Users', value: '2,543' },
  { label: 'Active Now', value: '842' },
  { label: 'Pending MFA', value: '45' },
  { label: 'Locked Accounts', value: '12' },
];

export default function AdminUsersScreen() {
  const { hasPermission } = useSession();

  if (!hasPermission('admin:users:read')) {
    return <Redirect href="/admin/login" />;
  }

  return (
    <View style={styles.root}>
      <View style={styles.topBar}>
        <Text style={styles.pageTitle}>User Management</Text>
        <Pressable style={styles.addButton}><Text style={styles.addButtonText}>Add New User</Text></Pressable>
      </View>

      <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        <View style={styles.cardGrid}>
          {stats.map((stat) => (
            <View key={stat.label} style={styles.statCard}>
              <Text style={styles.statLabel}>{stat.label}</Text>
              <Text style={styles.statValue}>{stat.value}</Text>
            </View>
          ))}
        </View>

        <View style={styles.tableCard}>
          <View style={styles.tableHeader}>
            <Text style={styles.columnHead}>User</Text>
            <Text style={styles.columnHead}>Role</Text>
            <Text style={styles.columnHead}>Status</Text>
            <Text style={styles.columnHead}>Action</Text>
          </View>
          {adminUsers.map((user) => (
            <View key={user.id} style={styles.tableRow}>
              <View style={styles.userCell}>
                <Image source={user.avatarSource} style={styles.avatar} />
                <View>
                  <Text style={styles.userName}>{user.name}</Text>
                  <Text style={styles.userEmail}>{user.email}</Text>
                </View>
              </View>
              <Text style={styles.metaText}>{user.role}</Text>
              <Text style={styles.metaText}>{user.state}</Text>
              <Text style={styles.actionText}>Edit</Text>
            </View>
          ))}
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  topBar: { height: 64, borderBottomWidth: 1, borderBottomColor: colors.border, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 16 },
  pageTitle: { color: colors.text, fontSize: 24, fontWeight: '800' },
  addButton: { height: 40, paddingHorizontal: 14, borderRadius: 6, backgroundColor: colors.accent, alignItems: 'center', justifyContent: 'center' },
  addButtonText: { color: colors.text, fontWeight: '700' },
  content: { padding: 16, gap: 16 },
  cardGrid: { flexDirection: 'row', gap: 12, flexWrap: 'wrap' },
  statCard: { flex: 1, minWidth: 180, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, padding: 16 },
  statLabel: { color: colors.muted, fontSize: 12, textTransform: 'uppercase', fontFamily: 'monospace' },
  statValue: { color: colors.text, fontSize: 32, fontWeight: '700', marginTop: 8 },
  tableCard: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8, overflow: 'hidden' },
  tableHeader: { flexDirection: 'row', paddingHorizontal: 16, paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.background },
  columnHead: { flex: 1, color: colors.muted, fontSize: 12, fontFamily: 'monospace', textTransform: 'uppercase' },
  tableRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingVertical: 14, borderBottomWidth: 1, borderBottomColor: colors.border },
  userCell: { flex: 1.6, flexDirection: 'row', alignItems: 'center', gap: 12 },
  avatar: { width: 36, height: 36, borderRadius: 999, borderWidth: 1, borderColor: colors.border },
  userName: { color: colors.text, fontWeight: '600' },
  userEmail: { color: colors.muted, fontSize: 12 },
  metaText: { flex: 1, color: colors.text, fontSize: 13 },
  actionText: { flex: 1, color: colors.accentSoft, fontSize: 13 },
});
