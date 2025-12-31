# Style Refactoring Plan - Hybrid CSS Approach

## Executive Summary

**Goal:** Reduce inline style bloat by 60-70% through strategic extraction of repeated patterns into CSS classes while maintaining theme integration and TypeScript safety.

**Current State:** 748 inline style blocks consuming ~4,900 lines across 16 files

**Target State:** ~150 inline style blocks + ~200 lines of reusable CSS

---

## Current State Analysis

### Inline Style Line Count by File

| File | Total Lines | Style Blocks | Est. Style Lines | % of File |
|------|-------------|--------------|------------------|-----------|
| components/IntegrationsPanel.tsx | 1,286 | 118 | 944 | 73% |
| App.tsx | 1,768 | 108 | 864 | 48% |
| components/ThingCard.tsx | 1,032 | 94 | 752 | 72% |
| components/SettingsPanels.tsx | 719 | 66 | 528 | 73% |
| components/EditKindModal.tsx | 272 | 41 | 328 | 120% |
| components/FriendsView.tsx | 507 | 39 | 312 | 61% |
| components/CommentsSection.tsx | 635 | 35 | 280 | 44% |
| components/EditThingModal.tsx | 379 | 30 | 240 | 63% |
| components/FeedView.tsx | 288 | 25 | 200 | 69% |
| components/ReactionComponents.tsx | 429 | 20 | 160 | 37% |
| components/AttributeInputs.tsx | 248 | 14 | 112 | 45% |
| components/EmojiPicker.tsx | 167 | 9 | 72 | 43% |
| components/Footer.tsx | 30 | 8 | 64 | 213% |
| components/BookmarksView.tsx | 102 | 7 | 56 | 54% |
| components/KindSelector.tsx | 87 | 3 | 24 | 27% |
| components/SettingsPage.tsx | 91 | 1 | 8 | 8% |

**Total:** 748 style blocks ≈ 4,920 estimated lines of inline styles

---

## Top Repeated Patterns (200+ occurrences)

From analysis, these 10 patterns account for ~300 style blocks:

1. **Flex Row Center** (36 occurrences)
   ```tsx
   { display: 'flex', alignItems: 'center', gap: 8 }
   ```

2. **Flex Column** (26 occurrences)
   ```tsx
   { display: 'flex', flexDirection: 'column', gap: 8 }
   ```

3. **Card Container** (24 occurrences)
   ```tsx
   { padding: 16, background: theme.bgCard, borderRadius: 8, border: `1px solid ${theme.border}` }
   ```

4. **Form Label** (53+ occurrences via textMuted)
   ```tsx
   { display: 'block', fontSize: 13, color: theme.textMuted, marginBottom: 4 }
   ```

5. **Input Field** (20+ form inputs)
   ```tsx
   { width: '100%', padding: '8px 12px', border: `1px solid ${theme.borderInput}`, borderRadius: 6 }
   ```

6. **Button Primary** (30+ buttons)
   ```tsx
   { padding: '10px 20px', background: theme.accent, color: theme.accentText, border: 'none', borderRadius: 6 }
   ```

7. **Text Sizes** (122+ text colors)
   - fontSize: 12, 13, 14, 16, 18, 20
   - color: theme.text, theme.textMuted, theme.textSecondary

8. **Spacing** (80+ margin/padding)
   - gap: 4, 6, 8, 12, 16, 20, 24
   - marginBottom: 4, 8, 12, 16, 24, 32

---

## Proposed Hybrid Architecture

### 1. CSS Variables (Extend existing in index.html)

Already have theme variables. Add design tokens:

```css
:root {
  /* Spacing Scale */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --space-8: 32px;

  /* Border Radius */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;
  --radius-xl: 12px;

  /* Font Sizes */
  --text-xs: 11px;
  --text-sm: 12px;
  --text-base: 13px;
  --text-md: 14px;
  --text-lg: 16px;
  --text-xl: 18px;
  --text-2xl: 20px;
}
```

### 2. Utility Classes (New: web/src/styles.css)

Create ~50 utility classes:

```css
/* Layout */
.flex { display: flex; }
.flex-col { flex-direction: column; }
.items-center { align-items: center; }
.items-start { align-items: flex-start; }
.justify-between { justify-content: space-between; }
.justify-center { justify-content: center; }
.flex-1 { flex: 1; }
.flex-wrap { flex-wrap: wrap; }

/* Spacing */
.gap-1 { gap: var(--space-1); }
.gap-2 { gap: var(--space-2); }
.gap-3 { gap: var(--space-3); }
.gap-4 { gap: var(--space-4); }
.gap-6 { gap: var(--space-6); }

.p-2 { padding: var(--space-2); }
.p-4 { padding: var(--space-4); }
.p-6 { padding: var(--space-6); }

.mb-1 { margin-bottom: var(--space-1); }
.mb-2 { margin-bottom: var(--space-2); }
.mb-3 { margin-bottom: var(--space-3); }
.mb-4 { margin-bottom: var(--space-4); }
.mb-6 { margin-bottom: var(--space-6); }
.mt-6 { margin-top: var(--space-6); }
.mt-8 { margin-top: var(--space-8); }

/* Text */
.text-xs { font-size: var(--text-xs); }
.text-sm { font-size: var(--text-sm); }
.text-base { font-size: var(--text-base); }
.text-md { font-size: var(--text-md); }
.text-lg { font-size: var(--text-lg); }
.text-xl { font-size: var(--text-xl); }
.text-2xl { font-size: var(--text-2xl); }

.text-muted { color: var(--text-muted); }
.text-subtle { color: var(--text-subtle); }
.font-medium { font-weight: 500; }
.font-semibold { font-weight: 600; }

/* Misc */
.w-full { width: 100%; }
.rounded-sm { border-radius: var(--radius-sm); }
.rounded { border-radius: var(--radius-md); }
.rounded-lg { border-radius: var(--radius-lg); }
.rounded-xl { border-radius: var(--radius-xl); }
.cursor-pointer { cursor: pointer; }
.overflow-auto { overflow: auto; }
.text-center { text-align: center; }
```

### 3. Component Classes (For complex patterns)

```css
/* Cards */
.card {
  padding: var(--space-4);
  background: var(--bg-card);
  border-radius: var(--radius-lg);
  border: 1px solid var(--border);
}

.card-hover {
  transition: background 0.15s;
}
.card-hover:hover {
  background: var(--bg-hover);
}

/* Forms */
.label {
  display: block;
  font-size: var(--text-base);
  color: var(--text-muted);
  margin-bottom: var(--space-1);
}

.input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border-input);
  border-radius: var(--radius-md);
  background: var(--bg-input);
  color: var(--text);
  font-size: var(--text-md);
  box-sizing: border-box;
}

.input:focus {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

/* Buttons */
.btn {
  padding: 10px 20px;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  font-size: var(--text-md);
  transition: opacity 0.15s;
}

.btn:hover:not(:disabled) {
  opacity: 0.9;
}

.btn:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.btn-primary {
  background: var(--accent);
  color: var(--accent-text);
}

.btn-secondary {
  background: var(--bg-hover);
  color: var(--text);
}

.btn-danger {
  background: var(--error-bg);
  color: var(--error-text);
}

.btn-sm {
  padding: 6px 12px;
  font-size: var(--text-sm);
}

/* Code blocks */
.code-inline {
  background: var(--bg-muted);
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  font-family: monospace;
  font-size: var(--text-sm);
}
```

### 4. Keep Inline For:

- Dynamic values from props/state
- Computed styles (widths, positions)
- One-off unique styles
- Complex interactions (hover states with theme colors not in CSS vars)

---

## Implementation Plan

### Phase 1: Foundation (Day 1)

**Files to create:**
1. ✅ `web/src/styles.css` - Main stylesheet
2. ✅ Update `web/index.html` - Add CSS variables, import styles.css

**Deliverables:**
- 50 utility classes
- 10 component classes
- Extended CSS variables

**Metrics:**
- 0 files refactored yet
- Foundation ready

---

### Phase 2: High-Impact Files (Day 2-3)

**Priority 1 - Top 5 heaviest files (>500 estimated style lines):**

1. **IntegrationsPanel.tsx** (944 lines → ~300 target)
   - Extract: Cards, buttons, form inputs, labels
   - Keep inline: Toggle styles, dynamic webhook states

2. **App.tsx** (864 lines → ~250 target)
   - Extract: Layout grids, auth forms, doc navigation
   - Keep inline: Route-dependent styles

3. **ThingCard.tsx** (752 lines → ~250 target)
   - Extract: Card containers, photo layouts, metadata displays
   - Keep inline: Template-specific rendering, dynamic photo viewer

4. **SettingsPanels.tsx** (528 lines → ~180 target)
   - Extract: Tab navigation, form layouts, key displays
   - Keep inline: Conditional key states

5. **EditKindModal.tsx** (328 lines → ~120 target)
   - Extract: Modal structure, form fields, attribute lists
   - Keep inline: Emoji picker integration

**Expected reduction:** ~2,500 lines → ~1,100 lines (56% reduction)

---

### Phase 3: Medium Files (Day 4)

**Priority 2 - Medium weight (150-300 estimated lines):**

6. FriendsView.tsx (312 → ~120)
7. CommentsSection.tsx (280 → ~100)
8. EditThingModal.tsx (240 → ~90)
9. FeedView.tsx (200 → ~80)
10. ReactionComponents.tsx (160 → ~70)

**Expected reduction:** ~1,200 lines → ~460 lines (62% reduction)

---

### Phase 4: Polish (Day 5)

**Priority 3 - Remaining files:**

11. AttributeInputs.tsx
12. EmojiPicker.tsx
13. Footer.tsx
14. BookmarksView.tsx
15. KindSelector.tsx
16. SettingsPage.tsx (already minimal)

**Expected reduction:** ~336 lines → ~150 lines (55% reduction)

---

## Success Metrics

### Before:
- Total source lines: ~8,500
- Inline style lines: ~4,920 (58% of codebase)
- Style blocks: 748
- Bundle size: ~322 KB

### After (Projected):
- Total source lines: ~5,800 (32% reduction)
- Inline style lines: ~1,710 (30% of codebase)
- Style blocks: ~220 (71% reduction)
- CSS file: ~200 lines
- Bundle size: ~285 KB (estimated -12%)

### Key Wins:
1. **Developer Experience:** Write `className="flex items-center gap-2"` instead of 3-line style objects
2. **Performance:** Browser can cache CSS, less JS to parse
3. **Consistency:** Design system enforced through classes
4. **Maintainability:** Change spacing scale in one place
5. **Bundle Size:** ~37 KB reduction in JS

---

## Migration Strategy

### For Each Component:

1. **Identify patterns** - Find repeated style blocks
2. **Replace with classes** - Use existing utilities where possible
3. **Test theme switching** - Ensure dark/light mode still works
4. **Verify build** - Run `npm run build` after each file
5. **Commit** - Small commits per file or feature

### Example Migration:

**Before:**
```tsx
<div style={{
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  padding: 16,
  background: theme.bgCard,
  borderRadius: 8,
  border: `1px solid ${theme.border}`
}}>
```

**After:**
```tsx
<div className="card flex items-center gap-2">
```

**For dynamic colors (keep inline):**
```tsx
<button style={{ background: theme.accent, color: theme.accentText }} className="btn">
```

---

## Risk Mitigation

1. **Theme Integration:** All color CSS variables already exist in index.html
2. **Type Safety:** Can create `cn()` utility for className composition later
3. **Rollback:** Git commits per file allow easy revert
4. **Testing:** Build after each file ensures no breakage
5. **Progressive:** Can stop at any phase if issues arise

---

## Post-Refactor Opportunities

1. Add `clsx` or `classnames` library for dynamic class composition
2. Consider TypeScript type definitions for className values
3. Document design system in separate style guide
4. Add CSS linting (stylelint) for consistency
5. Explore component variants using class composition

---

## Timeline

- **Phase 1 (Foundation):** 2 hours
- **Phase 2 (High-Impact):** 6 hours
- **Phase 3 (Medium):** 4 hours
- **Phase 4 (Polish):** 2 hours

**Total Estimated Time:** 14 hours over 5 days

---

**Status:** ✅ Plan Complete - Ready for Implementation
**Next Step:** Create styles.css foundation
