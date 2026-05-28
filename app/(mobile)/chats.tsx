import { Feather, MaterialIcons } from '@expo/vector-icons';
import { Link } from 'expo-router';
import { Image, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, conversations } from '@/components/secure-ui';

const items = [
  {
    id: 'jason',
    unread: true,
    name: 'Alexander Pierce',
    time: '10:42 AM',
    preview: 'The deployment keys have been rotated.',
    avatarSource: conversations[0].avatarSource,
    online: true,
  },
  {
    id: 'security-ops',
    unread: false,
    name: 'Security Ops (Group)',
    time: 'Yesterday',
    preview: 'System automated ping: All nodes nominal.',
    group: 'SO',
  },
  {
    id: 'northstar',
    unread: false,
    name: 'Elena Rostova',
    time: 'Tue',
    preview: 'Awaiting final sign-off on the Q3 protocol updates.',
    avatarSource: conversations[1].avatarSource,
  },
  {
    id: 'archive',
    unread: false,
    name: 'Archived Logs',
    time: 'Oct 12',
    preview: 'Data retention cycle completed.',
    icon: 'archive',
  },
];

export default function ChatsScreen() {
  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <MaterialIcons name="shield" size={20} color={colors.accentSoft} />
          <Text style={styles.headerTitle}>Messages</Text>
        </View>
        <Pressable style={styles.composeButton}>
          <Feather name="edit-3" size={18} color={colors.text} />
        </Pressable>
      </View>

      <ScrollView contentContainerStyle={styles.content} showsVerticalScrollIndicator={false}>
        <View style={styles.searchWrap}>
          <Feather name="search" size={16} color="#45464d" style={styles.searchIcon} />
          <TextInput placeholder="Search conversations" placeholderTextColor="#45464d" style={styles.searchInput} />
        </View>

        <View>
          {items.map((item) => (
            <Link key={item.id} href={item.id === 'security-ops' ? '/chat/jason' : `/chat/${item.id}`} asChild>
              <Pressable style={({ pressed }) => [styles.row, pressed && styles.pressed]}>
                <View style={styles.avatarWrap}>
                  {item.avatarSource ? (
                    <Image source={item.avatarSource} style={styles.avatar} />
                  ) : (
                    <View style={[styles.avatar, styles.groupAvatar]}>
                      {item.icon ? <MaterialIcons name={item.icon as never} size={18} color="#94A3B8" /> : <Text style={styles.groupText}>{item.group}</Text>}
                    </View>
                  )}
                  {item.online ? <View style={styles.onlineDot} /> : null}
                </View>

                <View style={styles.threadBody}>
                  <View style={styles.topLine}>
                    <Text style={styles.name}>{item.name}</Text>
                    <Text style={styles.time}>{item.time}</Text>
                  </View>
                  <View style={styles.previewLine}>
                    <MaterialIcons name="lock" size={14} color="#45464d" />
                    <Text style={[styles.preview, item.unread && styles.previewUnread]} numberOfLines={1}>{item.preview}</Text>
                  </View>
                </View>
              </Pressable>
            </Link>
          ))}
        </View>
      </ScrollView>

    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  header: {
    height: 56,
    backgroundColor: colors.background,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
    paddingHorizontal: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  headerTitle: { color: colors.accentSoft, fontSize: 20, fontWeight: '700' },
  composeButton: { width: 40, height: 40, borderRadius: 999, alignItems: 'center', justifyContent: 'center' },
  content: { paddingHorizontal: 16, paddingTop: 16, paddingBottom: 24 },
  searchWrap: { marginBottom: 4, height: 40, justifyContent: 'center', borderBottomWidth: 1, borderBottomColor: colors.border },
  searchIcon: { position: 'absolute', left: 0, top: 12 },
  searchInput: { color: colors.text, paddingLeft: 28, paddingVertical: 8, fontSize: 13 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: colors.border },
  pressed: { backgroundColor: '#0e0e10' },
  avatarWrap: { width: 48, height: 48, borderRadius: 999, position: 'relative', overflow: 'visible' },
  avatar: { width: 48, height: 48, borderRadius: 999, borderWidth: 1, borderColor: colors.border, backgroundColor: colors.surfaceContainerHigh, alignItems: 'center', justifyContent: 'center' },
  groupAvatar: { backgroundColor: colors.primaryContainer },
  groupText: { color: colors.primary, fontWeight: '700', fontSize: 12 },
  onlineDot: { position: 'absolute', right: 0, bottom: 0, width: 12, height: 12, borderRadius: 999, backgroundColor: '#0284C7', borderWidth: 2, borderColor: colors.background },
  threadBody: { flex: 1, minWidth: 0 },
  topLine: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'baseline', gap: 8 },
  name: { flex: 1, color: colors.text, fontSize: 15, fontWeight: '600' },
  time: { color: colors.accentSoft, fontSize: 12, fontFamily: 'monospace' },
  previewLine: { flexDirection: 'row', alignItems: 'center', gap: 4, marginTop: 4 },
  preview: { color: '#c6c6cd', fontSize: 13, flex: 1 },
  previewUnread: { color: colors.text, fontWeight: '600' },
});
