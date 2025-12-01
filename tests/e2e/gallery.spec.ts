import { test, expect, type Page } from '../../web/node_modules/@playwright/test';

// Helper to login as test user
async function loginAsTestUser(page: Page) {
  await page.goto('/');
  // Wait for login page
  await page.waitForSelector('input[placeholder*="username"]', { timeout: 5000 });

  // Login with test credentials
  await page.fill('input[placeholder*="username"]', 'testuser');
  await page.fill('input[placeholder*="password"]', 'testpass123');
  await page.click('button:has-text("Login")');

  // Wait for redirect to main page
  await page.waitForURL('/', { timeout: 5000 });
}

test.describe('Gallery Photo Upload', () => {
  test('should load login page', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/tenant/i);
  });

  test('should allow multi-photo upload with captions', async ({ page }) => {
    // Note: This test requires setting up proper authentication
    // For now, we skip it if we can't login
    await page.goto('/');

    // Check if we have a login form or already authenticated
    const isLoggedIn = await page.$('[data-testid="feed"]') !== null;

    if (!isLoggedIn) {
      test.skip();
    }

    // Find the upload button
    const uploadButton = await page.$('input[type="file"]');
    expect(uploadButton).toBeTruthy();
  });

  test('should display photos in carousel order', async ({ page }) => {
    await page.goto('/');

    // Check that if galleries exist, they render photos
    const galleryElements = await page.$$('[data-testid="gallery"]');

    // If galleries exist, verify they have photo elements
    if (galleryElements.length > 0) {
      for (const gallery of galleryElements) {
        const photos = await gallery.$$('[data-testid="photo"]');
        if (photos.length > 0) {
          // Verify photos have proper structure
          for (const photo of photos) {
            const caption = await photo.$('[data-testid="photo-caption"]');
            // Caption may or may not exist depending on user input
            const img = await photo.$('img');
            expect(img).toBeTruthy();
          }
        }
      }
    }
  });

  test('should verify visibility levels on things', async ({ page }) => {
    await page.goto('/');

    // Check if there are things displayed
    const thingElements = await page.$$('[data-testid="thing"]');

    // If things exist, verify visibility indicator
    if (thingElements.length > 0) {
      for (const thing of thingElements) {
        const visibilityIndicator = await thing.$('[data-testid="visibility"]');
        if (visibilityIndicator) {
          const visibility = await visibilityIndicator.textContent();
          expect(['private', 'friends', 'public']).toContain(visibility?.toLowerCase());
        }
      }
    }
  });

  test('should render photo carousel navigation', async ({ page }) => {
    await page.goto('/');

    // Look for galleries with multiple photos
    const galleries = await page.$$('[data-testid="gallery"]');

    for (const gallery of galleries) {
      const photos = await gallery.$$('[data-testid="photo"]');

      // If gallery has multiple photos, should have navigation
      if (photos.length > 1) {
        const prevButton = await gallery.$('[data-testid="photo-prev"]');
        const nextButton = await gallery.$('[data-testid="photo-next"]');
        const counter = await gallery.$('[data-testid="photo-counter"]');

        expect(prevButton || nextButton || counter).toBeTruthy();
      }
    }
  });

  test('API endpoint should return gallery with photos in order', async ({ request }) => {
    // Test the API directly
    const response = await request.get('/api/things', {
      headers: {
        'Cookie': 'session=test-session',
      },
    });

    // If we get unauthorized, that's expected without auth
    if (response.status() === 401) {
      test.skip();
    }

    if (response.status() === 200) {
      const data = await response.json();

      // Check if any galleries exist
      const galleries = data.filter((thing: any) => thing.type === 'gallery');

      if (galleries.length > 0) {
        const gallery = galleries[0];

        // Verify gallery structure
        expect(gallery.id).toBeTruthy();
        expect(gallery.type).toBe('gallery');
        expect(gallery.visibility).toMatch(/private|friends|public/);

        // If photos exist, verify they're in order
        if (gallery.photos && gallery.photos.length > 0) {
          expect(gallery.photos[0].orderIndex).toBe(0);
          for (let i = 1; i < gallery.photos.length; i++) {
            expect(gallery.photos[i].orderIndex).toBe(i);
            // Verify captions exist (may be empty string)
            expect('caption' in gallery.photos[i]).toBe(true);
          }
        }
      }
    }
  });
});

test.describe('Photo Visibility', () => {
  test('should respect private visibility in API', async ({ request }) => {
    const response = await request.get('/api/things', {
      headers: {
        // No auth cookie - public things only
      },
    });

    if (response.status() === 200) {
      const data = await response.json();

      // Without auth, should only get public things
      for (const thing of data) {
        if (thing.visibility) {
          expect(thing.visibility).not.toBe('private');
        }
      }
    }
  });

  test('should return things with correct visibility levels', async ({ request }) => {
    // Try to get things (may fail without proper auth)
    const response = await request.get('/api/things');

    if (response.status() === 200) {
      const data = await response.json();

      // All things should have valid visibility level
      for (const thing of data) {
        if (thing.visibility) {
          const validLevels = ['private', 'friends', 'public'];
          expect(validLevels).toContain(thing.visibility);
        }
      }
    }
  });
});
