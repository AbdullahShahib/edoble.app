import { Feather } from '@expo/vector-icons';
import type { ReactNode } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';

const stitchAssets = {
  chatAvatar01: require('../assets/stitch/chat_avatar_01.jpg'),
  chatAvatar02: require('../assets/stitch/chat_avatar_02.jpg'),
  chatAvatar03: require('../assets/stitch/chat_avatar_03.jpg'),
  chatAvatar04: require('../assets/stitch/chat_avatar_04.jpg'),
  chatAvatar05: require('../assets/stitch/chat_avatar_05.jpg'),
  chatAvatar06: require('../assets/stitch/chat_avatar_06.jpg'),
  chatAvatar07: require('../assets/stitch/chat_avatar_07.jpg'),
  chatAvatar08: require('../assets/stitch/chat_avatar_08.jpg'),
  adminUserAvatar01: require('../assets/stitch/admin_user_avatar_01.jpg'),
  adminUserAvatar02: require('../assets/stitch/admin_user_avatar_02.jpg'),
  jasonAvatar01: require('../assets/stitch/jason_avatar_01.jpg'),
  stitchScreenshot01: require('../assets/stitch/2f24c91ed45f7fb2b0765e293e1cc8a4.jpg'),
  stitchScreenshot02: require('../assets/stitch/Screenshot 2026-05-19 144914.png'),
} as const;

export const colors = {
  background: '#09090B',
  surface: '#0F172A',
  surfaceElevated: '#111827',
  surfaceContainerHigh: '#2A2A2B',
  border: '#1E293B',
  text: '#F8FAFC',
  muted: '#94A3B8',
  accent: '#0284C7',
  accentSoft: '#0EA5E9',
  primary: '#BEC6E0',
  primaryContainer: '#0F172A',
  secondary: '#93CCFF',
  secondaryContainer: '#3198DC',
  onSecondaryContainer: '#002C47',
  outline: '#909097',
  success: '#10B981',
  warning: '#F59E0B',
  danger: '#F43F5E',
};

export const securityStats = [
  { label: 'Pilot adoption', value: '100%', detail: 'All verified users active' },
  { label: 'Uptime', value: '99.9%', detail: 'Encrypted relay healthy' },
  { label: 'Media success', value: '98.4%', detail: 'Large file transfer SLA' },
  { label: 'Admin action', value: '< 2 min', detail: 'Onboarding and wipe time' },
];

export const conversations = [
  {
    id: 'jason',
    name: 'Jason Lee',
    role: 'R&D Engineering',
    preview: 'CAD bundle rewrapped in the vault. Timer set to 5 minutes.',
    time: '2m',
    unread: 2,
    status: 'online',
    avatarSource: stitchAssets.jasonAvatar01,
  },
  {
    id: 'northstar',
    name: 'Northstar Legal',
    role: 'Corporate Counsel',
    preview: 'Redlines uploaded. Waiting on final signature hash.',
    time: '11m',
    unread: 0,
    status: 'secure',
    avatarSource: stitchAssets.chatAvatar01,
  },
  {
    id: 'board',
    name: 'Board Briefing',
    role: 'Executive group',
    preview: 'Notification previews remain hidden on lock screen.',
    time: '25m',
    unread: 1,
    status: 'ephemeral',
    avatarSource: stitchAssets.chatAvatar02,
  },
];

export const messageThreads: Record<string, Array<{ id: string; sender: string; body: string; time: string; tone: 'self' | 'other' }>> = {
  jason: [
    { id: '1', sender: 'Jason Lee', body: 'Encrypted CAD package is in the vault. Do you want me to set the message to expire after review?', time: '09:12', tone: 'other' },
    { id: '2', sender: 'You', body: 'Yes. Use a 5 minute timer and keep the preview hidden from lock screen notifications.', time: '09:13', tone: 'self' },
    { id: '3', sender: 'Jason Lee', body: 'Confirmed. I also rotated the attachment key and flagged the transfer in the audit trail.', time: '09:14', tone: 'other' },
  ],
  northstar: [
    { id: '1', sender: 'Northstar Legal', body: 'The merger draft is encrypted end to end. Only the assigned reviewers can open it.', time: '08:41', tone: 'other' },
    { id: '2', sender: 'You', body: 'Perfect. Hold on the unsend window until we have sign-off.', time: '08:43', tone: 'self' },
  ],
  board: [
    { id: '1', sender: 'Chief of Staff', body: 'Executive summary is ready. Push notifications should continue to hide sender names.', time: 'Yesterday', tone: 'other' },
  ],
};

export const adminUsers = [
  { id: 'u1', name: 'Jason Lee', email: 'jason.lee@edoble.corp', role: 'employee', state: 'Active', device: 'Compliant device', avatarSource: stitchAssets.adminUserAvatar01 },
  { id: 'u2', name: 'Mara Chen', email: 'mara.chen@edoble.corp', role: 'admin', state: 'Active', device: '2 trusted devices', avatarSource: stitchAssets.adminUserAvatar02 },
  { id: 'u3', name: 'Evan Brooks', email: 'evan.brooks@edoble.corp', role: 'employee', state: 'Revoked', device: 'Wipe pending', avatarSource: stitchAssets.chatAvatar03 },
];

export const auditAlerts = [
  { id: 'a1', label: 'Screenshot detected', detail: 'Legal review on board thread', time: '04:18', tone: 'warning' },
  { id: 'a2', label: 'Unauthorized login attempt', detail: 'Blocked on revoked device', time: '03:52', tone: 'danger' },
  { id: 'a3', label: 'Remote wipe completed', detail: 'Lost phone cleared in 32 seconds', time: 'Yesterday', tone: 'success' },
];

export function ScreenShell({ title, subtitle, right, children }: { title: string; subtitle?: string; right?: ReactNode; children: ReactNode }) {
  return (
    <ScrollView contentContainerStyle={styles.screen} showsVerticalScrollIndicator={false}>
      <View style={styles.topRow}>
        <View style={{ flex: 1 }}>
          <Text style={styles.kicker}>Edoble Messenger</Text>
          <Text style={styles.screenTitle}>{title}</Text>
          {subtitle ? <Text style={styles.screenSubtitle}>{subtitle}</Text> : null}
        </View>
        {right}
      </View>
      {children}
    </ScrollView>
  );
}

export function Panel({ children, style }: { children: ReactNode; style?: object }) {
  return <View style={[styles.panel, style]}>{children}</View>;
}

export function Badge({ label, tone = 'neutral' }: { label: string; tone?: 'neutral' | 'success' | 'warning' | 'danger' }) {
  return (
    <View style={[styles.badge, styles[`badge_${tone}` as const]]}>
      <Text style={[styles.badgeText, styles[`badgeText_${tone}` as const]]}>{label}</Text>
    </View>
  );
}

export function MetricCard({ label, value, detail, tone = 'neutral' }: { label: string; value: string; detail: string; tone?: 'neutral' | 'accent' | 'success' | 'warning' }) {
  return (
    <View style={[styles.metricCard, styles[`metric_${tone}` as const]]}>
      <Text style={styles.metricLabel}>{label}</Text>
      <Text style={styles.metricValue}>{value}</Text>
      <Text style={styles.metricDetail}>{detail}</Text>
    </View>
  );
}

export function Field({ label, placeholder, secureTextEntry = false, value, onChangeText, multiline = false, autoCapitalize = 'sentences', keyboardType = 'default', textContentType, autoComplete, returnKeyType }: { label: string; placeholder: string; secureTextEntry?: boolean; value: string; onChangeText: (value: string) => void; multiline?: boolean; autoCapitalize?: 'none' | 'sentences' | 'words' | 'characters'; keyboardType?: 'default' | 'email-address' | 'numeric' | 'phone-pad'; textContentType?: 'emailAddress' | 'password' | 'oneTimeCode' | 'name'; autoComplete?: 'email' | 'password' | 'one-time-code' | 'name'; returnKeyType?: 'done' | 'next' | 'go' }) {
  return (
    <View style={styles.field}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput
        value={value}
        onChangeText={onChangeText}
        placeholder={placeholder}
        placeholderTextColor="#64748B"
        secureTextEntry={secureTextEntry}
        multiline={multiline}
        autoCapitalize={autoCapitalize}
        keyboardType={keyboardType}
        textContentType={textContentType}
        autoComplete={autoComplete}
        returnKeyType={returnKeyType}
        style={[styles.input, multiline && styles.inputMultiline]}
      />
    </View>
  );
}

export function PrimaryButton({ label, onPress, icon, disabled = false }: { label: string; onPress: () => void; icon?: keyof typeof Feather.glyphMap; disabled?: boolean }) {
  return (
    <Pressable disabled={disabled} onPress={onPress} style={({ pressed }) => [styles.primaryButton, disabled && styles.buttonDisabled, pressed && !disabled && styles.pressed]}>
      {icon ? <Feather name={icon} size={16} color={colors.text} /> : null}
      <Text style={styles.primaryButtonText}>{label}</Text>
    </Pressable>
  );
}

export function GhostButton({ label, onPress, disabled = false }: { label: string; onPress: () => void; disabled?: boolean }) {
  return (
    <Pressable disabled={disabled} onPress={onPress} style={({ pressed }) => [styles.ghostButton, disabled && styles.buttonDisabled, pressed && !disabled && styles.pressed]}>
      <Text style={styles.ghostButtonText}>{label}</Text>
    </Pressable>
  );
}

export function RowPill({ label }: { label: string }) {
  return (
    <View style={styles.rowPill}>
      <Text style={styles.rowPillText}>{label}</Text>
    </View>
  );
}

export { stitchAssets };

const styles = StyleSheet.create({
  screen: {
    flexGrow: 1,
    padding: 20,
    gap: 16,
    backgroundColor: colors.background,
  },
  topRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 16,
  },
  kicker: {
    color: colors.accentSoft,
    textTransform: 'uppercase',
    letterSpacing: 2,
    fontSize: 11,
    marginBottom: 6,
    fontWeight: '700',
  },
  screenTitle: {
    color: colors.text,
    fontSize: 30,
    lineHeight: 36,
    fontWeight: '800',
  },
  screenSubtitle: {
    color: colors.muted,
    marginTop: 8,
    lineHeight: 20,
    maxWidth: 760,
  },
  panel: {
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.surface,
    borderRadius: 16,
    padding: 16,
    gap: 14,
  },
  badge: {
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderRadius: 999,
    alignSelf: 'flex-start',
    borderWidth: 1,
  },
  badge_neutral: { backgroundColor: '#0B1120', borderColor: colors.border },
  badge_success: { backgroundColor: 'rgba(16,185,129,0.14)', borderColor: 'rgba(16,185,129,0.32)' },
  badge_warning: { backgroundColor: 'rgba(245,158,11,0.14)', borderColor: 'rgba(245,158,11,0.32)' },
  badge_danger: { backgroundColor: 'rgba(244,63,94,0.14)', borderColor: 'rgba(244,63,94,0.32)' },
  badgeText: { fontSize: 12, fontWeight: '700' },
  badgeText_neutral: { color: colors.text },
  badgeText_success: { color: '#34D399' },
  badgeText_warning: { color: '#FBBF24' },
  badgeText_danger: { color: '#FB7185' },
  metricCard: {
    flex: 1,
    minWidth: 150,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 16,
    padding: 14,
    backgroundColor: colors.surfaceElevated,
    gap: 8,
  },
  metric_neutral: {},
  metric_accent: { borderColor: 'rgba(2,132,199,0.55)' },
  metric_success: { borderColor: 'rgba(16,185,129,0.55)' },
  metric_warning: { borderColor: 'rgba(245,158,11,0.55)' },
  metricLabel: { color: colors.muted, fontSize: 12, textTransform: 'uppercase', letterSpacing: 1 },
  metricValue: { color: colors.text, fontSize: 24, fontWeight: '800' },
  metricDetail: { color: colors.muted, lineHeight: 18 },
  field: { gap: 8 },
  fieldLabel: { color: colors.text, fontSize: 13, fontWeight: '700' },
  input: {
    backgroundColor: '#050816',
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    color: colors.text,
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 15,
  },
  inputMultiline: {
    minHeight: 96,
    textAlignVertical: 'top',
  },
  primaryButton: {
    minHeight: 44,
    borderRadius: 12,
    backgroundColor: colors.accent,
    paddingHorizontal: 16,
    alignItems: 'center',
    justifyContent: 'center',
    flexDirection: 'row',
    gap: 8,
  },
  primaryButtonText: { color: colors.text, fontWeight: '800' },
  ghostButton: {
    minHeight: 44,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
    paddingHorizontal: 16,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#0B1220',
  },
  ghostButtonText: { color: colors.text, fontWeight: '700' },
  buttonDisabled: { opacity: 0.5 },
  rowPill: {
    borderRadius: 999,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: '#0B1220',
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  rowPillText: { color: colors.text, fontSize: 12, fontWeight: '700' },
  pressed: { opacity: 0.86, transform: [{ scale: 0.99 }] },
});
