# app.tsx refactor

The issue is clear: App.tsx is 8,462 lines - way too large. This needs to be split into logical modules. Here's what I'd suggest: Proposed structure:

```
src/
├── components/
│   ├── ThingCard.tsx
│   ├── EditThingModal.tsx
│   ├── EditKindModal.tsx
│   ├── KindSelector.tsx
│   ├── PhotoUploadModal.tsx
│   └── Sidebar.tsx
├── pages/
│   ├── ProfilePage.tsx
│   ├── FeedPage.tsx
│   ├── BookmarksPage.tsx
│   ├── SettingsPage.tsx
│   └── DocsPage.tsx
├── docs/
│   ├── AboutContent.tsx
│   ├── APIDocsContent.tsx
│   ├── AIAgentsContent.tsx
│   └── DeploymentContent.tsx
├── hooks/
│   └── useThings.ts (data fetching logic)
├── App.tsx (just routing + layout shell)
└── ...existing files
This would make each file ~200-500 lines max, much easier to work with. Want me to plan this refactoring in detail, or should we tackle it piece by piece starting with the easiest extractions (like the docs content components)?
```