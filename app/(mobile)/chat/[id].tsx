import { Feather, MaterialIcons } from '@expo/vector-icons';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useMemo, useState } from 'react';
import { Image, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';

import { colors, conversations, messageThreads } from '@/components/secure-ui';

export default function ChatDetailScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const conversation = conversations.find((item) => item.id === id) ?? conversations[0];
  const messages = messageThreads[conversation.id] ?? messageThreads.jason;
  const [secondsLeft, setSecondsLeft] = useState(4 * 60 + 32);
  const [message, setMessage] = useState('');
  const totalSeconds = 5 * 60;

  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsLeft((value) => (value > 0 ? value - 1 : value));
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const countdown = useMemo(() => {
    const minutes = Math.floor(secondsLeft / 60);
    const seconds = secondsLeft % 60;
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  }, [secondsLeft]);

  const burnWidth: `${number}%` = `${(secondsLeft / totalSeconds) * 100}%`;

  return (
    <View style={styles.root}>
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Pressable style={styles.backButton}>
            <Feather name="arrow-left" size={18} color="#c6c6cd" />
          </Pressable>
          <View style={styles.personRow}>
            <View style={styles.avatarWrap}>
              <Image source={conversation.avatarSource} style={styles.avatar} />
              <View style={styles.onlineDot} />
            </View>
            <View>
              <Text style={styles.name}>{conversation.name.split(' ')[0]}</Text>
              <Text style={styles.online}>Online</Text>
            </View>
          </View>
        </View>
        <View style={styles.headerActions}>
          <Pressable style={styles.iconButton}><Feather name="phone" size={18} color="#c6c6cd" /></Pressable>
          <Pressable style={styles.iconButton}><Feather name="more-vertical" size={18} color="#c6c6cd" /></Pressable>
        </View>
      </View>

      <View style={styles.noticeWrap}>
        <View style={styles.noticePill}>
          <MaterialIcons name="lock" size={14} color={colors.secondary} />
          <Text style={styles.noticeText}>E2E ENCRYPTED SESSION</Text>
        </View>
      </View>

      <ScrollView contentContainerStyle={styles.thread} showsVerticalScrollIndicator={false}>
        <View style={styles.dateRow}>
          <Text style={styles.dateLabel}>TODAY</Text>
          <View style={styles.dateLine} />
        </View>

        <View style={styles.incomingRow}>
          <Image source={conversation.avatarSource} style={styles.smallAvatar} />
          <View style={styles.incomingStack}>
            <View style={styles.incomingBubble}>
              <Text style={styles.messageText}>The latest security audits are ready for review. Access is restricted.</Text>
            </View>
          </View>
        </View>

        <View style={styles.outgoingStack}>
          <View style={styles.outgoingBubble}>
            <Text style={styles.messageText}>Understood. I'll initiate the secure download protocol now.</Text>
          </View>
          <View style={styles.fileBubble}>
            <View style={styles.fileIcon}><MaterialIcons name="folder-zip" size={18} color={colors.text} /></View>
            <View>
              <Text style={styles.fileTitle}>Audit_Logs_Q3.enc</Text>
              <Text style={styles.fileMeta}>14.2 MB • SHA-256</Text>
            </View>
          </View>
          <View style={styles.timeRow}>
            <Text style={styles.timeText}>10:42 AM</Text>
            <MaterialIcons name="done-all" size={14} color={colors.secondary} />
          </View>
        </View>

        <View style={[styles.incomingRow, styles.mt]}> 
          <Image source={conversation.avatarSource} style={[styles.smallAvatar, styles.transparent]} />
          <View style={styles.incomingStack}>
            <View style={styles.incomingBubble}>
              <View style={styles.lockManifestRow}>
                <View style={styles.fileIcon}><MaterialIcons name="lock" size={18} color={colors.secondary} /></View>
                <View>
                  <Text style={styles.fileTitle}>Decryption_Key_Manifest.key</Text>
                  <Text style={styles.fileMeta}>Encrypted Payload</Text>
                  <View style={styles.hexBox}><Text style={styles.hexText}>hx7f...9a2c</Text></View>
                </View>
              </View>
            </View>
            <Text style={styles.timeText}>10:45 AM</Text>
          </View>
        </View>

        <View style={[styles.incomingRow, styles.mtLarge]}>
          <Image source={conversation.avatarSource} style={[styles.smallAvatar, styles.transparent]} />
          <View style={styles.incomingStack}>
            <View style={[styles.incomingBubble, styles.timerBubble]}>
              <View style={styles.burnBar}><View style={[styles.burnProgress, { width: burnWidth }]} /></View>
              <View style={styles.timerRow}>
                <MaterialIcons name="local-fire-department" size={14} color="#f87171" />
                <Text style={styles.timerText}>{countdown}</Text>
              </View>
              <Text style={styles.messageText}>Review quickly. This node will purge the key in 5 minutes to maintain OPSEC.</Text>
            </View>
          </View>
        </View>
      </ScrollView>

      <View style={styles.footer}>
        <View style={styles.footerRow}>
          <Pressable style={styles.addButton}><MaterialIcons name="add-circle" size={18} color="#c6c6cd" /></Pressable>
          <View style={styles.inputWrap}>
            <TextInput placeholder="Secure message..." placeholderTextColor="#7c7c84" value={message} onChangeText={setMessage} style={styles.input} multiline />
            <View style={styles.inputLock}><MaterialIcons name="lock" size={16} color="#c6c6cd" /></View>
          </View>
          <Pressable style={styles.sendButton}><MaterialIcons name="send" size={18} color={colors.text} /></Pressable>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.background },
  header: { height: 56, flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingHorizontal: 16, borderBottomWidth: 1, borderBottomColor: colors.border, backgroundColor: colors.background },
  headerLeft: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  backButton: { width: 32, height: 32, alignItems: 'center', justifyContent: 'center', borderRadius: 999 },
  personRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  avatarWrap: { width: 32, height: 32, position: 'relative' },
  avatar: { width: 32, height: 32, borderRadius: 999, borderWidth: 1, borderColor: colors.border },
  onlineDot: { position: 'absolute', right: -1, bottom: -1, width: 10, height: 10, borderRadius: 999, backgroundColor: '#10b981', borderWidth: 2, borderColor: colors.background },
  name: { color: colors.secondary, fontSize: 20, fontWeight: '700' },
  online: { color: '#10b981', fontSize: 12, fontFamily: 'monospace' },
  headerActions: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  iconButton: { width: 36, height: 36, borderRadius: 999, alignItems: 'center', justifyContent: 'center' },
  noticeWrap: { alignItems: 'center', paddingTop: 12 },
  noticePill: { flexDirection: 'row', alignItems: 'center', gap: 6, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  noticeText: { color: colors.muted, fontSize: 12, fontFamily: 'monospace', letterSpacing: 0.5 },
  thread: { padding: 16, paddingBottom: 24, gap: 18 },
  dateRow: { position: 'relative', alignItems: 'center', justifyContent: 'center', marginVertical: 4 },
  dateLabel: { color: colors.muted, fontSize: 12, fontFamily: 'monospace', paddingHorizontal: 8, backgroundColor: colors.background, zIndex: 1 },
  dateLine: { position: 'absolute', top: '50%', left: 0, right: 0, height: 1, backgroundColor: colors.border },
  incomingRow: { flexDirection: 'row', alignItems: 'flex-end', gap: 8, maxWidth: '85%' },
  incomingStack: { gap: 8 },
  smallAvatar: { width: 32, height: 32, borderRadius: 999, borderWidth: 1, borderColor: colors.border },
  transparent: { opacity: 1 },
  incomingBubble: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.border, borderRadius: 6, borderBottomLeftRadius: 0, padding: 12 },
  outgoingStack: { alignSelf: 'flex-end', gap: 12, maxWidth: '85%', alignItems: 'flex-end' },
  outgoingBubble: { backgroundColor: colors.accent, borderRadius: 6, borderTopRightRadius: 0, padding: 12 },
  messageText: { color: colors.text, lineHeight: 20 },
  fileBubble: { flexDirection: 'row', alignItems: 'center', gap: 10, backgroundColor: colors.accent, borderRadius: 6, padding: 12, minWidth: 240 },
  fileIcon: { width: 36, height: 36, borderRadius: 6, backgroundColor: '#0369A1', alignItems: 'center', justifyContent: 'center' },
  fileTitle: { color: colors.text, fontSize: 13, fontWeight: '700' },
  fileMeta: { color: 'rgba(248,250,252,0.8)', fontSize: 10, fontFamily: 'monospace', marginTop: 2 },
  timeRow: { flexDirection: 'row', alignItems: 'center', gap: 6 },
  timeText: { color: colors.muted, fontSize: 10, fontFamily: 'monospace' },
  mt: { marginTop: 4 },
  mtLarge: { marginTop: 8 },
  lockManifestRow: { flexDirection: 'row', alignItems: 'flex-start', gap: 10 },
  hexBox: { marginTop: 8, borderWidth: 1, borderColor: colors.border, backgroundColor: colors.background, borderRadius: 4, padding: 8, width: 200 },
  hexText: { color: colors.secondary, fontSize: 10, fontFamily: 'monospace' },
  timerBubble: { position: 'relative', overflow: 'hidden' },
  burnBar: { height: 2, backgroundColor: colors.border, width: '100%', position: 'absolute', top: 0, left: 0 },
  burnProgress: { height: '100%', backgroundColor: 'rgba(239,68,68,0.8)' },
  timerRow: { flexDirection: 'row', alignItems: 'center', gap: 4, marginTop: 4, marginBottom: 8 },
  timerText: { color: '#f87171', fontSize: 12, fontFamily: 'monospace', fontWeight: '700' },
  footer: { borderTopWidth: 1, borderTopColor: colors.border, backgroundColor: colors.background, padding: 12 },
  footerRow: { flexDirection: 'row', alignItems: 'flex-end', gap: 8 },
  addButton: { marginBottom: 4, width: 32, height: 32, alignItems: 'center', justifyContent: 'center' },
  inputWrap: { flex: 1, position: 'relative' },
  input: { minHeight: 40, maxHeight: 120, color: colors.text, borderBottomWidth: 1, borderBottomColor: colors.border, paddingVertical: 8, paddingRight: 34, fontSize: 15, backgroundColor: 'transparent' },
  inputLock: { position: 'absolute', right: 8, bottom: 8, opacity: 0.5 },
  sendButton: { width: 40, height: 40, borderRadius: 999, backgroundColor: colors.accent, alignItems: 'center', justifyContent: 'center', marginBottom: 0 },
});
