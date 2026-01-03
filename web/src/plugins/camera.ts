import { Camera, CameraResultType, CameraSource, Photo } from '@capacitor/camera';
import { Capacitor } from '@capacitor/core';

export interface CapturedPhoto {
  webPath: string;
  format: string;
  base64?: string;
}

/**
 * Check if camera is available
 */
export function isCameraAvailable(): boolean {
  return Capacitor.isNativePlatform();
}

/**
 * Take a photo using the device camera
 */
export async function takePhoto(options?: {
  quality?: number;
  allowEditing?: boolean;
}): Promise<CapturedPhoto | null> {
  try {
    const photo = await Camera.getPhoto({
      quality: options?.quality ?? 90,
      allowEditing: options?.allowEditing ?? false,
      resultType: CameraResultType.Uri,
      source: CameraSource.Camera,
      saveToGallery: false,
    });

    return photoToResult(photo);
  } catch (error) {
    // User cancelled or error occurred
    console.log('Camera cancelled or error:', error);
    return null;
  }
}

/**
 * Pick a photo from the device gallery
 */
export async function pickFromGallery(options?: {
  quality?: number;
  allowEditing?: boolean;
}): Promise<CapturedPhoto | null> {
  try {
    const photo = await Camera.getPhoto({
      quality: options?.quality ?? 90,
      allowEditing: options?.allowEditing ?? false,
      resultType: CameraResultType.Uri,
      source: CameraSource.Photos,
    });

    return photoToResult(photo);
  } catch (error) {
    // User cancelled or error occurred
    console.log('Gallery picker cancelled or error:', error);
    return null;
  }
}

/**
 * Pick multiple photos from gallery
 */
export async function pickMultipleFromGallery(options?: {
  quality?: number;
  limit?: number;
}): Promise<CapturedPhoto[]> {
  try {
    const result = await Camera.pickImages({
      quality: options?.quality ?? 90,
      limit: options?.limit ?? 10,
    });

    return result.photos.map((photo) => ({
      webPath: photo.webPath ?? '',
      format: photo.format,
    }));
  } catch (error) {
    console.log('Multiple gallery picker cancelled or error:', error);
    return [];
  }
}

/**
 * Show action sheet to choose between camera and gallery
 */
export async function captureOrPick(options?: {
  quality?: number;
  allowEditing?: boolean;
}): Promise<CapturedPhoto | null> {
  try {
    const photo = await Camera.getPhoto({
      quality: options?.quality ?? 90,
      allowEditing: options?.allowEditing ?? false,
      resultType: CameraResultType.Uri,
      source: CameraSource.Prompt, // Shows action sheet
      promptLabelHeader: 'Photo',
      promptLabelPhoto: 'From Gallery',
      promptLabelPicture: 'Take Photo',
    });

    return photoToResult(photo);
  } catch (error) {
    console.log('Capture/pick cancelled or error:', error);
    return null;
  }
}

/**
 * Check camera permissions
 */
export async function checkCameraPermissions(): Promise<{
  camera: 'granted' | 'denied' | 'prompt';
  photos: 'granted' | 'denied' | 'prompt';
}> {
  const result = await Camera.checkPermissions();
  return {
    camera: result.camera,
    photos: result.photos,
  };
}

/**
 * Request camera permissions
 */
export async function requestCameraPermissions(): Promise<{
  camera: 'granted' | 'denied' | 'prompt';
  photos: 'granted' | 'denied' | 'prompt';
}> {
  const result = await Camera.requestPermissions();
  return {
    camera: result.camera,
    photos: result.photos,
  };
}

/**
 * Convert Capacitor Photo to our result type
 */
function photoToResult(photo: Photo): CapturedPhoto {
  return {
    webPath: photo.webPath ?? '',
    format: photo.format,
    base64: photo.base64String,
  };
}

/**
 * Convert a web path to a Blob for uploading
 */
export async function webPathToBlob(webPath: string): Promise<Blob> {
  const response = await fetch(webPath);
  return response.blob();
}

/**
 * Convert a web path to a File for form uploads
 */
export async function webPathToFile(
  webPath: string,
  filename: string
): Promise<File> {
  const blob = await webPathToBlob(webPath);
  return new File([blob], filename, { type: blob.type });
}
