import { router } from 'expo-router';
import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { Badge, Field, GhostButton, Panel, PrimaryButton, RowPill, ScreenShell, colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

function formatRemaining(ms: number) {
  const totalSeconds = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

export default function LoginScreen() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const { canAttempt, getRemainingLockoutMs, registerFailedAttempt, clearFailedAttempts } = useSession();

  const isEmailValid = /\S+@\S+\.\S+/.test(email);
  const isCorpDomain = email.toLowerCase().endsWith('@edoble.corp');
  const isLocked = !canAttempt('employee');
  const lockoutMs = getRemainingLockoutMs('employee');
  const canSubmit = isEmailValid && password.length >= 8 && isCorpDomain && !isLocked;

  const handleMfa = () => {
    if (isLocked) {
      setError(`Too many attempts. Try again in ${formatRemaining(lockoutMs)}.`);
      return;
    }

    if (!isEmailValid) {
      registerFailedAttempt('employee');
      setError('Enter a valid corporate email address.');
      return;
    }

    if (!isCorpDomain) {
      registerFailedAttempt('employee');
      setError('Use your @edoble.corp corporate account.');
      return;
    }

    if (password.length < 8) {
      registerFailedAttempt('employee');
      setError('Password must be at least 8 characters.');
      return;
    }

    clearFailedAttempts('employee');
    setError('');
    try {
      if (typeof window !== 'undefined') window.localStorage.setItem('edoble.pending.username', email);
    } catch {}
    router.push('/mfa-challenge');
  };

  return (
    <View style={styles.root}>
      <View style={styles.glowA} />
      <View style={styles.glowB} />
      <ScreenShell
        title="Secure login terminal"
        subtitle="Sign in with corporate credentials to verify MFA and unlock the encrypted workspace."
        right={<Badge label="Hardened auth" tone="success" />}
      >
        <View style={styles.heroGrid}>
          <Panel style={styles.loginPanel}>
            <View style={styles.panelTopRow}>
              <RowPill label="Encrypted entry" />
              <RowPill label="Corp SSO + MFA" />
            </View>
            <Text style={styles.heroTitle}>Edoble Messenger</Text>
              <Text style={styles.heroCopy}>A secure workspace for legal, engineering, and operations teams that need fast collaboration without exposing sensitive content.</Text>
            <View style={styles.stack}>
              <Field label="Corporate email" placeholder="name@company.com" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" textContentType="emailAddress" autoComplete="email" returnKeyType="next" />
              <Field label="Password" placeholder="••••••••••••" value={password} onChangeText={setPassword} secureTextEntry autoCapitalize="none" textContentType="password" autoComplete="password" returnKeyType="go" />
            </View>
            <View style={styles.actionRow}>
              <PrimaryButton label="Verify MFA" icon="shield" onPress={handleMfa} disabled={!canSubmit} />
              <GhostButton label="Admin access" onPress={() => router.push('/admin/login')} />
            </View>
            {error ? <Text style={styles.errorText}>{error}</Text> : null}
            {isLocked ? <Text style={styles.lockoutText}>Login is temporarily locked. Remaining: {formatRemaining(lockoutMs)}</Text> : null}
            <Text style={styles.smallPrint}>Local device keys are unlocked only after MFA succeeds. Message content never leaves the client in plaintext.</Text>
          </Panel>

          <View style={styles.sideColumn}>
            <Panel>
              <Text style={styles.panelHeading}>Security posture</Text>
              <View style={styles.sideStats}>
                <View style={styles.sideStatRow}><Text style={styles.sideStatLabel}>Screen capture</Text><Text style={styles.sideStatValue}>Blocked + alerted</Text></View>
                <View style={styles.sideStatRow}><Text style={styles.sideStatLabel}>Device lock</Text><Text style={styles.sideStatValue}>Remote wipe ready</Text></View>
                <View style={styles.sideStatRow}><Text style={styles.sideStatLabel}>Notification previews</Text><Text style={styles.sideStatValue}>Hidden on lock screen</Text></View>
                <View style={styles.sideStatRow}><Text style={styles.sideStatLabel}>Retention</Text><Text style={styles.sideStatValue}>Policy controlled</Text></View>
              </View>
            </Panel>
            <Panel>
              <Text style={styles.panelHeading}>Product controls</Text>
              <View style={styles.chipsRow}>
                <RowPill label="MFA required" />
                <RowPill label="Session locked" />
                <RowPill label="Audit enabled" />
              </View>
              <Text style={styles.smallPrint}>The interface is tuned for production use: minimal surface area, clear policy controls, and no design-reference artifacts in the live shell.</Text>
            </Panel>
          </View>
        </View>
      </ScreenShell>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: colors.background,
  },
  glowA: {
    position: 'absolute',
    top: -120,
    left: -40,
    width: 320,
    height: 320,
    borderRadius: 999,
    backgroundColor: 'rgba(2,132,199,0.18)',
  },
  glowB: {
    position: 'absolute',
    right: -100,
    bottom: 80,
    width: 280,
    height: 280,
    borderRadius: 999,
    backgroundColor: 'rgba(15,23,42,0.85)',
  },
  heroGrid: {
    gap: 16,
    flexDirection: 'row',
    flexWrap: 'wrap',
  },
  loginPanel: {
    flex: 1,
    minWidth: 340,
    gap: 16,
  },
  sideColumn: {
    flex: 0.85,
    minWidth: 280,
    gap: 16,
  },
  panelTopRow: {
    flexDirection: 'row',
    gap: 8,
    flexWrap: 'wrap',
  },
  heroTitle: {
    color: colors.text,
    fontSize: 34,
    lineHeight: 38,
    fontWeight: '800',
  },
  heroCopy: {
    color: colors.muted,
    lineHeight: 22,
    maxWidth: 560,
  },
  stack: {
    gap: 14,
  },
  actionRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 12,
  },
  errorText: {
    color: '#FB7185',
    fontWeight: '600',
  },
  lockoutText: {
    color: '#FBBF24',
    fontWeight: '600',
  },
  smallPrint: {
    color: '#64748B',
    lineHeight: 18,
  },
  panelHeading: {
    color: colors.text,
    fontSize: 16,
    fontWeight: '800',
    marginBottom: 4,
  },
  sideStats: {
    gap: 12,
  },
  sideStatRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  sideStatLabel: {
    color: colors.muted,
    flex: 1,
  },
  sideStatValue: {
    color: colors.text,
    fontWeight: '700',
    textAlign: 'right',
    flex: 1,
  },
  chipsRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
});
