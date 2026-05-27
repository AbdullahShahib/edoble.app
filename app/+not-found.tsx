import { Link, Stack } from 'expo-router';
import { StyleSheet, Text, View } from 'react-native';

import { colors } from '@/components/secure-ui';

export default function NotFoundScreen() {
  return (
    <>
      <Stack.Screen options={{ title: 'Secure route not found' }} />
      <View style={styles.container}>
        <Text style={styles.title}>This secure route does not exist.</Text>
        <Text style={styles.copy}>Return to the login terminal or open the workspace if you are already authenticated.</Text>
        <Link href="/login" style={styles.link}>
          Go to login
        </Link>
      </View>
    </>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
    backgroundColor: colors.background,
  },
  title: {
    color: colors.text,
    fontSize: 20,
    fontWeight: 'bold',
  },
  copy: {
    color: colors.muted,
    marginTop: 10,
    textAlign: 'center',
    maxWidth: 420,
  },
  link: {
    marginTop: 16,
    paddingVertical: 12,
    color: colors.accentSoft,
    fontWeight: '700',
  },
});
