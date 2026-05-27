import { Image, StyleSheet, Text, View } from 'react-native';

import { colors, conversations } from '@/components/secure-ui';

export default function ContactsScreen() {
  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <Text style={styles.title}>Contacts</Text>
      </View>
      <View style={styles.content}>
        {conversations.map((contact) => (
          <View key={contact.id} style={styles.row}>
            <Image source={contact.avatarSource} style={styles.avatar} />
            <View style={styles.meta}>
              <Text style={styles.name}>{contact.name}</Text>
              <Text style={styles.role}>{contact.role}</Text>
            </View>
          </View>
        ))}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  header: { height: 56, borderBottomWidth: 1, borderBottomColor: colors.border, justifyContent: 'center', paddingHorizontal: 16 },
  title: { color: colors.text, fontSize: 20, fontWeight: '700' },
  content: { padding: 16, gap: 12 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 12, padding: 12, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 8 },
  avatar: { width: 40, height: 40, borderRadius: 999, borderWidth: 1, borderColor: colors.border },
  meta: { gap: 2 },
  name: { color: colors.text, fontWeight: '600' },
  role: { color: colors.muted, fontSize: 12 },
});
