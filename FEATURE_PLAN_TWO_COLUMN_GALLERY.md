# Feature Plan: Two-Column Photo Gallery Layout

## Goal
Display photo/gallery posts in a Facebook-style layout with the gallery on the left and post content on the right when viewing in detail mode on desktop.

## Current Behavior
- Photo posts display with photo above content in a single column
- Max width: 700px for all post types

## Desired Behavior
- Photo/gallery posts in detail view on desktop: two-column layout
  - Left: Photo gallery (sticky, larger display)
  - Right: Post metadata, caption, content, attributes
- Max width: 1200px for photo posts in detail view
- Mobile: Keep existing single-column layout
- Feed view: Keep existing single-column layout

## Technical Approach

**Key insight: Move ALL hooks to top level, use conditional rendering for UI only**

### 1. PostPage.tsx changes

```typescript
// Around line 718-722
const kind = thing ? getKind(thing.type) : undefined
const isPhotoPost = kind?.template === 'photo' && thing?.photos && thing.photos.length > 0

return (
  <div style={{ maxWidth: (!isMobile && isPhotoPost) ? 1200 : 700, margin: '0 auto', ... }}>
```

```typescript
// Around line 793
<ThingCard
  thing={thing}
  kind={kind}
  onEdit={() => setEditingThing(thing)}
  onDelete={() => { onDelete(thing.id); onBack() }}
  onUpdateThing={updateThing}
  theme={theme}
  isDetailView={true}
  twoColumnLayout={isPhotoPost && !isMobile}
/>
```

### 2. ThingCard component changes

```typescript
// Around line 2007-2021
function ThingCard({
  thing,
  kind,
  onEdit,
  onDelete,
  onUpdateThing,
  theme,
  isDetailView = false,
  twoColumnLayout = false,  // ADD THIS
}: {
  thing: Thing
  kind: Kind | undefined
  isDetailView?: boolean
  twoColumnLayout?: boolean  // ADD THIS
  onEdit: () => void
  onDelete: () => void
  onUpdateThing: (thing: Thing) => void
  theme: Theme
}) {
```

### 3. Photo template section changes

```typescript
// Around line 2346-2368
// PHOTO template - image/video display
if (template === 'photo') {
  // Handle gallery with multiple photos
  if (thing.photos && thing.photos.length > 0) {
    // CRITICAL: Call ALL hooks at top level BEFORE any conditionals
    const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0)
    const [viewerOpen, setViewerOpen] = useState(false)
    const currentPhoto = thing.photos[currentPhotoIndex]
    const isVideo = currentPhoto.contentType?.startsWith('video/')

    // Photo Viewer Modal - keyboard navigation
    useEffect(() => {
      if (!viewerOpen) return
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') setViewerOpen(false)
        else if (e.key === 'ArrowLeft') setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1))
        else if (e.key === 'ArrowRight') setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1))
      }
      window.addEventListener('keydown', handleKeyDown)
      return () => window.removeEventListener('keydown', handleKeyDown)
    }, [viewerOpen, thing.photos])

    // NOW add conditional rendering for two-column layout
    if (twoColumnLayout && isDetailView) {
      // Return two-column JSX here
      // - Copy PhotoViewer component definition
      // - Grid layout with gallery left, content right
      // - Reuse existing photo display and navigation code
    }

    // Existing single-column layout continues below...
    const PhotoViewer = () => { ... }
    return ( ... existing single column layout ... )
  }
}
```

## Files to Modify
- `web/src/App.tsx` only
  - Lines ~720: Add `isPhotoPost` detection and conditional max-width
  - Lines ~793: Add `twoColumnLayout` prop
  - Lines 2007-2021: Add `twoColumnLayout` to function signature
  - Lines 2346-2610: Restructure photo template with hooks at top level

## What NOT to do
- ❌ Don't add hooks inside conditionals (breaks React rules)
- ❌ Don't create new separate components (keeps it simple)
- ❌ Don't modify backend
- ❌ Don't change feed view layout
- ❌ Don't change mobile layout

## Testing Checklist
- [ ] Desktop detail view shows two columns for photo posts
- [ ] Mobile stays single column
- [ ] Feed view stays single column
- [ ] Photo viewer modal still works
- [ ] Carousel navigation works
- [ ] Logout button works
- [ ] `/api/auth/status` doesn't hang
- [ ] Default kinds (note, link, task, photo, gallery) appear after login

## Risk Mitigation
- Test with `curl http://localhost:8069/api/auth/status` after each build
- If it hangs, immediately revert with `git checkout web/src/App.tsx`
- Build incrementally and test after each change
- Remember: **Hooks MUST be at top level, before ANY conditionals**

## Implementation Steps

1. **Add isPhotoPost detection in PostPage** (test)
2. **Add twoColumnLayout prop to ThingCard signature** (test)
3. **Restructure photo template to call hooks at top level** (test)
4. **Add two-column conditional rendering** (test)
5. **Build, restart server, and test thoroughly**

## Success Criteria
- Photo posts show Facebook-style two-column layout on desktop detail view
- No API hangs or infinite loops
- All existing functionality still works
- Clean code with proper React hook usage
