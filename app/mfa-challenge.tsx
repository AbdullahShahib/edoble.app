import { router } from 'expo-router';
import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { Badge, Field, Panel, PrimaryButton, RowPill, ScreenShell, colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

function formatRemaining(ms: number) {
  const totalSeconds = Math.ceil(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

export default function MfaChallengeScreen() {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const { signInEmployee, canAttempt, getRemainingLockoutMs, registerFailedAttempt, clearFailedAttempts } = useSession();

  const canSubmit = /^\d{6}$/.test(code);
  const isLocked = !canAttempt('mfa');
  const lockoutMs = getRemainingLockoutMs('mfa');

  const handleUnlock = () => {
    if (isLocked) {
      setError(`Too many MFA attempts. Try again in ${formatRemaining(lockoutMs)}.`);
      return;
    }

    if (!canSubmit) {
      registerFailedAttempt('mfa');
      setError('Enter the 6-digit code from your authenticator.');
      return;
    }

    clearFailedAttempts('mfa');
    setError('');
    signInEmployee();
    router.replace('/chats');
  };

  return (
    <View style={styles.root}>
      <ScreenShell
        title="MFA verification"
        subtitle="A second factor gates the key unlock path. Users never see raw cryptographic material, only the result of the challenge."
        right={<Badge label="Challenge required" tone="warning" />}
      >
        <View style={styles.container}>
          <Panel style={styles.primaryPanel}>
            <RowPill label="Step 2 of 2" />
            <Text style={styles.heading}>Enter your 6-digit token</Text>
            <Text style={styles.copy}>A code was sent to your registered authenticator. The session will only proceed after this challenge is satisfied.</Text>
            <Field label="MFA token" placeholder="Enter 6-digit code" value={code} onChangeText={setCode} keyboardType="numeric" textContentType="oneTimeCode" autoComplete="one-time-code" returnKeyType="go" autoCapitalize="none" />
            <View style={styles.actions}>
              <PrimaryButton label="Unlock workspace" icon="lock" onPress={handleUnlock} disabled={!canSubmit || isLocked} />
              <Pressable onPress={() => router.replace('/login')}>
                <Text style={styles.link}>Back to login</Text>
              </Pressable>
            </View>
            {error ? <Text style={styles.errorText}>{error}</Text> : null}
            {isLocked ? <Text style={styles.lockoutText}>MFA is temporarily locked. Remaining: {formatRemaining(lockoutMs)}</Text> : null}
          </Panel>
          <Panel style={styles.secondaryPanel}>
            <Text style={styles.panelHeading}>Session policy</Text>
            <Text style={styles.copy}>Session tokens, key pairs, and app state are pinned to the verified identity and can be revoked instantly from the admin console.</Text>
            <View style={styles.infoRows}>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>Push content</Text><Text style={styles.infoValue}>Hidden</Text></View>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>Local keychain</Text><Text style={styles.infoValue}>Encrypted</Text></View>
              <View style={styles.infoRow}><Text style={styles.infoLabel}>Revocation path</Text><Text style={styles.infoValue}>Immediate lock</Text></View>
            </View>
          </Panel>
        </View>
      </ScreenShell>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  container: { gap: 16, flexDirection: 'row', flexWrap: 'wrap' },
  primaryPanel: { flex: 1, minWidth: 340, gap: 16 },
  secondaryPanel: { flex: 0.75, minWidth: 280, gap: 12 },
  heading: { color: colors.text, fontSize: 26, lineHeight: 32, fontWeight: '800' },
  copy: { color: colors.muted, lineHeight: 21 },
  actions: { flexDirection: 'row', alignItems: 'center', gap: 14, flexWrap: 'wrap' },
  link: { color: colors.accentSoft, fontWeight: '700' },
  errorText: { color: '#FB7185', fontWeight: '600' },
  lockoutText: { color: '#FBBF24', fontWeight: '600' },
  panelHeading: { color: colors.text, fontSize: 16, fontWeight: '800' },
  infoRows: { gap: 12, marginTop: 4 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  infoLabel: { color: colors.muted },
  infoValue: { color: colors.text, fontWeight: '700' },
});
