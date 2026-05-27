import { Feather } from '@expo/vector-icons';
import { Redirect, Tabs } from 'expo-router';
import { useEffect } from 'react';
import { View } from 'react-native';

import { colors } from '@/components/secure-ui';
import { useSession } from '@/components/session';

export default function MobileLayout() {
  const { isSessionReady, isAuthenticated, hasPermission, touchSession } = useSession();

  useEffect(() => {
    if (isAuthenticated) {
      touchSession();
    }
  }, [isAuthenticated, touchSession]);

  if (!isSessionReady) {
    return <View style={{ flex: 1, backgroundColor: colors.background }} />;
  }

  if (!isAuthenticated || !hasPermission('chat:read')) {
    return <Redirect href="/login" />;
  }

  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarActiveTintColor: colors.accentSoft,
        tabBarInactiveTintColor: '#64748B',
        tabBarStyle: {
          backgroundColor: '#050816',
          borderTopColor: colors.border,
          height: 66,
          paddingTop: 8,
          paddingBottom: 10,
        },
        sceneStyle: { backgroundColor: colors.background },
      }}>
      <Tabs.Screen
        name="chats"
        options={{
          title: 'Chats',
          tabBarIcon: ({ color, size }) => <Feather name="message-circle" size={size} color={color} />,
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: 'Settings',
          tabBarIcon: ({ color, size }) => <Feather name="settings" size={size} color={color} />,
        }}
      />
      <Tabs.Screen
        name="contacts"
        options={{
          title: 'Contacts',
          tabBarIcon: ({ color, size }) => <Feather name="users" size={size} color={color} />,
        }}
      />
    </Tabs>
  );
}
