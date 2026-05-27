import { router } from 'expo-router';
import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { Badge, Field, Panel, PrimaryButton, RowPill, ScreenShell, colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

function formatRemaining(ms: number) {
  const totalSeconds = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

export default function AdminLoginScreen() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { signInAdmin, canAttempt, getRemainingLockoutMs, registerFailedAttempt, clearFailedAttempts } = useSession();

  const isEmailValid = /\S+@\S+\.\S+/.test(email);
  const isCorpDomain = email.toLowerCase().endsWith('@edoble.corp');
  const isLocked = !canAttempt('admin');
  const lockoutMs = getRemainingLockoutMs('admin');
  const canSubmit = isEmailValid && password.length >= 8 && isCorpDomain && !isLocked;

  const handleOpenDashboard = () => {
    if (isLocked) {
      setError(`Too many attempts. Try again in ${formatRemaining(lockoutMs)}.`);
      return;
    }

    if (!isEmailValid) {
      registerFailedAttempt('admin');
      setError('Enter a valid admin email address.');
      return;
    }

    if (!isCorpDomain) {
      registerFailedAttempt('admin');
      setError('Admin login requires an @edoble.corp account.');
      return;
    }

    if (password.length < 8) {
      registerFailedAttempt('admin');
      setError('Password must be at least 8 characters.');
      return;
    }

    clearFailedAttempts('admin');
    setError('');
    signInAdmin();
    router.replace('/admin/dashboard');
  };

  return (
    <View style={styles.root}>
      <ScreenShell
        title="Admin access"
        subtitle="The control plane is isolated from employee workflows and should only be reachable by authorized security staff."
        right={<Badge label="Privileged access" tone="warning" />}
      >
        <View style={styles.grid}>
          <Panel style={styles.loginPanel}>
            <RowPill label="Corporate SSO" />
            <Text style={styles.heading}>Sign in to the security console</Text>
            <Text style={styles.copy}>This panel handles onboarding, revocation, audit logging, and policy enforcement across every trusted device.</Text>
            <Field label="Admin email" placeholder="security.admin@company.com" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" textContentType="emailAddress" autoComplete="email" returnKeyType="next" />
            <Field label="Password" placeholder="••••••••••" value={password} onChangeText={setPassword} secureTextEntry autoCapitalize="none" textContentType="password" autoComplete="password" returnKeyType="go" />
            <PrimaryButton label="Open dashboard" icon="shield" onPress={handleOpenDashboard} disabled={!canSubmit} />
            {error ? <Text style={styles.errorText}>{error}</Text> : null}
            {isLocked ? <Text style={styles.lockoutText}>Admin login temporarily locked. Remaining: {formatRemaining(lockoutMs)}</Text> : null}
          </Panel>
          <Panel style={styles.sidePanel}>
            <Text style={styles.panelHeading}>Policy snapshot</Text>
            <View style={styles.infoRows}>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>RLS tables</Text><Text style={styles.infoValue}>Enabled</Text></View>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>Remote wipe</Text><Text style={styles.infoValue}>One click</Text></View>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>Screenshot alerts</Text><Text style={styles.infoValue}>Active</Text></View>
            </View>
          </Panel>
        </View>
      </ScreenShell>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  grid: { flexDirection: 'row', gap: 12, flexWrap: 'wrap' },
  loginPanel: { flex: 1, minWidth: 340, gap: 14 },
  sidePanel: { flex: 0.75, minWidth: 280, gap: 12 },
  heading: { color: colors.text, fontSize: 28, lineHeight: 34, fontWeight: '800' },
  copy: { color: colors.muted, lineHeight: 21 },
  panelHeading: { color: colors.text, fontSize: 18, fontWeight: '800' },
  infoRows: { gap: 12 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  infoLabel: { color: colors.muted },
  infoValue: { color: colors.text, fontWeight: '700' },
  errorText: { color: '#FB7185', fontWeight: '600' },
  lockoutText: { color: '#FBBF24', fontWeight: '600' },
});
