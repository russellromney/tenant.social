import { PushNotifications } from '@capacitor/push-notifications';
import { Capacitor } from '@capacitor/core';

export interface PushNotificationToken {
  value: string;
}

export interface PushNotificationData {
  id: string;
  title?: string;
  body?: string;
  data?: Record<string, unknown>;
}

/**
 * Check if push notifications are available (native platforms only)
 */
export function isPushAvailable(): boolean {
  return Capacitor.isNativePlatform();
}

/**
 * Request permission and register for push notifications
 * Returns the device token if successful
 */
export async function registerForPush(): Promise<string | null> {
  if (!isPushAvailable()) {
    console.log('Push notifications not available on this platform');
    return null;
  }

  try {
    // Request permission
    const permResult = await PushNotifications.requestPermissions();

    if (permResult.receive !== 'granted') {
      console.log('Push notification permission denied');
      return null;
    }

    // Register with APNS/FCM
    await PushNotifications.register();

    // Wait for registration token
    return new Promise((resolve) => {
      PushNotifications.addListener('registration', (token: PushNotificationToken) => {
        console.log('Push registration token:', token.value);
        resolve(token.value);
      });

      PushNotifications.addListener('registrationError', (error) => {
        console.error('Push registration error:', error);
        resolve(null);
      });
    });
  } catch (error) {
    console.error('Failed to register for push:', error);
    return null;
  }
}

/**
 * Set up listeners for incoming push notifications
 */
export function setupPushListeners(handlers: {
  onReceive?: (notification: PushNotificationData) => void;
  onTap?: (notification: PushNotificationData) => void;
}): void {
  if (!isPushAvailable()) return;

  // Notification received while app is in foreground
  PushNotifications.addListener('pushNotificationReceived', (notification) => {
    console.log('Push received:', notification);
    handlers.onReceive?.({
      id: notification.id,
      title: notification.title,
      body: notification.body,
      data: notification.data,
    });
  });

  // User tapped on notification
  PushNotifications.addListener('pushNotificationActionPerformed', (action) => {
    console.log('Push action performed:', action);
    handlers.onTap?.({
      id: action.notification.id,
      title: action.notification.title,
      body: action.notification.body,
      data: action.notification.data,
    });
  });
}

/**
 * Remove all push notification listeners
 */
export async function removePushListeners(): Promise<void> {
  await PushNotifications.removeAllListeners();
}
