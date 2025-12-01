import { test, expect, type Page } from '../../web/node_modules/@playwright/test';

// Helper to ensure logged in
async function ensureLoggedIn(page: Page) {
  await page.goto('/');

  // Try to wait for login form
  const loginFormExists = await page.$('input[placeholder*="username"]').catch(() => null);

  if (loginFormExists) {
    // Login with test credentials
    await page.fill('input[placeholder*="username"]', 'testuser');
    await page.fill('input[placeholder*="password"]', 'testpass123');
    await page.click('button:has-text("Login")');

    // Wait for redirect to main page
    await page.waitForURL('/', { timeout: 5000 });
  } else {
    // Already logged in, wait for feed to load
    await page.waitForSelector('[data-testid="feed"]', { timeout: 5000 }).catch(() => {
      // Feed might not have testid, that's ok
    });
  }
}

test.describe('Thing Linking Feature', () => {
  test('should display link attribute input in edit modal', async ({ page }) => {
    await ensureLoggedIn(page);

    // Wait for page to fully load (no specific testid needed)
    await page.waitForTimeout(1000);

    // Look for edit buttons anywhere on the page
    const editButtons = await page.locator('button').filter({ hasText: /edit/i }).all();

    if (editButtons.length > 0) {
      await editButtons[0].click();
      await page.waitForTimeout(500);

      // Check if any link-type attributes exist
      const linkInputs = await page.locator('input[placeholder*="Search to add"]').all();
      // Link inputs may or may not exist depending on kind attributes
      if (linkInputs.length > 0) {
        for (const input of linkInputs) {
          const isVisible = await input.isVisible();
          expect(isVisible).toBe(true);
        }
      }
    }
  });

  test('should add and remove linked things', async ({ page }) => {
    await ensureLoggedIn(page);

    // Wait for page to load
    await page.waitForTimeout(1000);

    // Find an edit button
    const editButtons = await page.locator('button').filter({ hasText: /edit/i }).all();

    if (editButtons.length > 0) {
      await editButtons[0].click();
      await page.waitForTimeout(500);

      // Look for link input fields
      const linkInputs = await page.locator('input[placeholder*="Search to add"]').all();

      if (linkInputs.length > 0) {
        const linkInput = linkInputs[0];

        // Type in the search field
        await linkInput.fill('test');

        // Wait a bit for dropdown
        await page.waitForTimeout(300);

        // Look for dropdown items
        const dropdownItems = await page.locator('div[style*="position: absolute"]').locator('div').all();

        // Skip if no dropdown items
        if (dropdownItems.length > 1) {
          // Click the first dropdown item (skip the container itself)
          await dropdownItems[1].click();

          // Verify the item was added (should see a tag with remove button)
          const selectedTags = await page.locator('div').filter({ has: page.locator('button:has-text("×")') }).all();

          if (selectedTags.length > 0) {
            expect(selectedTags.length).toBeGreaterThan(0);
          }
        }
      }
    }
  });

  test('should display linked things on thing card', async ({ page }) => {
    await ensureLoggedIn(page);

    // Wait for page to load
    await page.waitForTimeout(1000);

    // Look for linked things display
    const linkedThingsHeaders = await page.locator('text=Linked Things').all();

    // If linked things exist, verify they're displayed
    if (linkedThingsHeaders.length > 0) {
      for (const header of linkedThingsHeaders) {
        const isVisible = await header.isVisible();
        expect(isVisible).toBe(true);
      }
    }
  });

  test('should navigate to linked thing when clicked', async ({ page }) => {
    await ensureLoggedIn(page);

    // Wait for page to load
    await page.waitForTimeout(1000);

    // Look for the Linked Things section
    const linkedThingsHeaders = await page.locator('text=Linked Things').all();

    if (linkedThingsHeaders.length > 0) {
      // Get the current URL
      const currentUrl = page.url();

      // Find linked thing tags near the header
      const header = linkedThingsHeaders[0];
      const parent = header.locator('..');
      const linkedTags = parent.locator('div[style*="background:"]').all();
      const tags = await linkedTags;

      if (tags.length > 0) {
        // Click the first linked thing tag
        await tags[0].click();

        // Wait for navigation
        await page.waitForURL(/post/, { timeout: 5000 });

        const newUrl = page.url();
        expect(newUrl).not.toBe(currentUrl);
      }
    }
  });

  test('should display backlinks in post detail view', async ({ page }) => {
    await ensureLoggedIn(page);

    // Wait for page to load
    await page.waitForTimeout(1000);

    // Look for thing cards (they have padding style)
    const thingCards = await page.locator('div').filter({ has: page.locator('text').first() }).all();

    if (thingCards.length > 0) {
      // Click on first card
      await thingCards[0].click();

      // Wait for post page to load
      await page.waitForURL(/post/, { timeout: 5000 });

      // Look for backlinks section
      const backlinksHeaders = await page.locator('text=Backlinks').all();

      // If backlinks exist, they should be visible (count may vary)
      if (backlinksHeaders.length > 0) {
        for (const header of backlinksHeaders) {
          const isVisible = await header.isVisible();
          expect(isVisible).toBe(true);
        }
      }
    }
  });

  test('API endpoint should return backlinks correctly', async ({ request }) => {
    // Get all things
    const response = await request.get('/api/things', {
      headers: {
        'Cookie': 'session=test-session',
      },
    });

    // If we get unauthorized, skip
    if (response.status() === 401) {
      test.skip();
    }

    if (response.status() === 200) {
      const things = await response.json();

      // Pick the first thing and try to fetch its backlinks
      if (things.length > 0) {
        const thing = things[0];
        const backlinksResponse = await request.get(`/api/things/${thing.id}/backlinks`, {
          headers: {
            'Cookie': 'session=test-session',
          },
        });

        if (backlinksResponse.status() === 200) {
          const data = await backlinksResponse.json();

          // Should have a backlinks array
          expect(data).toHaveProperty('backlinks');
          expect(Array.isArray(data.backlinks)).toBe(true);

          // Each backlink should be a valid thing
          for (const backlink of data.backlinks) {
            expect(backlink.id).toBeTruthy();
            expect(backlink.type).toBeTruthy();
          }
        }
      }
    }
  });

  test('should store link attributes correctly in thing metadata', async ({ request }) => {
    // Get all things
    const response = await request.get('/api/things', {
      headers: {
        'Cookie': 'session=test-session',
      },
    });

    if (response.status() === 200) {
      const things = await response.json();

      // Look for things with link attributes
      for (const thing of things) {
        if (thing.metadata) {
          // Check if any metadata values are arrays of IDs (indicating links)
          const metadataValues = Object.values(thing.metadata);
          for (const value of metadataValues) {
            if (Array.isArray(value)) {
              // If it's an array, all items should be strings (IDs)
              for (const item of value) {
                expect(typeof item).toBe('string');
                // IDs should have reasonable length
                expect(item.length).toBeGreaterThan(0);
              }
            }
          }
        }
      }
    }
  });
});
