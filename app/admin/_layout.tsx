import { Feather } from '@expo/vector-icons';
import { Link, Redirect, Slot, usePathname } from 'expo-router';
import { useEffect } from 'react';
import { useWindowDimensions } from 'react-native';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

const links = [
  { href: '/admin/dashboard', label: 'Dashboard', icon: 'grid' as const },
  { href: '/admin/users', label: 'Users', icon: 'users' as const },
  { href: '/admin/audit-logs', label: 'Audit logs', icon: 'shield' as const },
] as const;

export default function AdminLayout() {
  const pathname = usePathname();
  const { width } = useWindowDimensions();
  const { isSessionReady, isAdminAuthenticated, hasPermission, touchSession } = useSession();

  useEffect(() => {
    if (isAdminAuthenticated) {
      touchSession();
    }
  }, [isAdminAuthenticated, touchSession]);

  if (pathname === '/admin/login') {
    return <Slot />;
  }

  if (!isSessionReady) {
    return <View style={{ flex: 1, backgroundColor: colors.background }} />;
  }

  if (!isAdminAuthenticated || !hasPermission('admin:access')) {
    return <Redirect href="/admin/login" />;
  }

  const compact = width < 980;

  return (
    <View style={[styles.shell, compact && styles.shellCompact]}>
      <View style={[styles.sidebar, compact && styles.sidebarCompact]}>
        <Text style={styles.brand}>Edoble Admin</Text>
        <Text style={styles.caption}>Zero-trust control plane</Text>
        <View style={styles.nav}>
          {links.map((link) => (
            <Link key={link.href} href={link.href} asChild>
              <Pressable style={({ pressed }) => [styles.navItem, pathname === link.href && styles.navItemActive, pressed && styles.pressed]}>
                <Feather name={link.icon} size={16} color={pathname === link.href ? colors.text : '#94A3B8'} />
                <Text style={[styles.navLabel, pathname === link.href && styles.navLabelActive]}>{link.label}</Text>
              </Pressable>
            </Link>
          ))}
        </View>
      </View>
      <View style={styles.content}>
        <Slot />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  shell: { flex: 1, flexDirection: 'row', backgroundColor: colors.background },
  shellCompact: { flexDirection: 'column' },
  sidebar: {
    width: 280,
    padding: 20,
    borderRightWidth: 1,
    borderRightColor: colors.border,
    backgroundColor: '#050816',
    gap: 12,
  },
  sidebarCompact: { width: '100%', borderRightWidth: 0, borderBottomWidth: 1, borderBottomColor: colors.border },
  brand: { color: colors.text, fontSize: 20, fontWeight: '800' },
  caption: { color: colors.muted },
  nav: { gap: 8, marginTop: 8 },
  navItem: { flexDirection: 'row', alignItems: 'center', gap: 10, padding: 12, borderRadius: 12, borderWidth: 1, borderColor: 'transparent' },
  navItemActive: { backgroundColor: 'rgba(2,132,199,0.16)', borderColor: 'rgba(2,132,199,0.4)' },
  navLabel: { color: '#94A3B8', fontWeight: '700' },
  navLabelActive: { color: colors.text },
  pressed: { opacity: 0.86 },
  content: { flex: 1, minWidth: 0 },
});
