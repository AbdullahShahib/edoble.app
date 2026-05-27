import { DefaultTheme, ThemeProvider } from '@react-navigation/native';
import { DMSerifDisplay_400Regular } from '@expo-google-fonts/dm-serif-display';
import { Inter_400Regular, Inter_500Medium, Inter_700Bold, Inter_800ExtraBold } from '@expo-google-fonts/inter';
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect } from 'react';
import 'react-native-reanimated';

import { SessionProvider } from '@/components/session';

SplashScreen.preventAutoHideAsync();

const edobleTheme = {
  ...DefaultTheme,
  colors: {
    ...DefaultTheme.colors,
    background: '#F7F6F2',
    card: '#FFFFFF',
    text: '#141414',
    border: '#E8E6E0',
    primary: '#C9A96E',
  },
};

export default function RootLayout() {
  const [loaded, error] = useFonts({
    DMSerifDisplay_400Regular,
    Inter_400Regular,
    Inter_500Medium,
    Inter_700Bold,
    Inter_800ExtraBold,
  });

  useEffect(() => {
    if (error) throw error;
  }, [error]);

  useEffect(() => {
    if (loaded) {
      SplashScreen.hideAsync();
    }
  }, [loaded]);

  if (!loaded) {
    return null;
  }

  return (
    <SessionProvider>
      <ThemeProvider value={edobleTheme}>
        <Stack
          screenOptions={{
            headerShown: false,
            contentStyle: { backgroundColor: '#F7F6F2' },
          }}>
          <Stack.Screen name="index" />
          <Stack.Screen name="login" />
          <Stack.Screen name="mfa-challenge" />
          <Stack.Screen name="(mobile)" />
          <Stack.Screen name="admin" />
          <Stack.Screen name="+not-found" />
        </Stack>
      </ThemeProvider>
    </SessionProvider>
  );
}
