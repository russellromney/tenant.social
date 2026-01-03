import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind, Thing, ReactionSummary } from '../types'
import { apiUrl, navigateTo } from '../api'
import { Markdown } from '../Markdown'
import { ReactionBar, BookmarkButton, EditedIndicator, EditHistoryModal } from './index'

// ThingCard Component - renders a Thing based on its Kind's template
export function ThingCard({
  thing,
  kind,
  onEdit,
  onDelete,
  onUpdateThing,
  theme,
  isDetailView = false,
}: {
  thing: Thing
  kind: Kind | undefined
  isDetailView?: boolean
  onEdit: () => void
  onDelete: () => void
  onUpdateThing: (thing: Thing) => void
  theme: Theme
}) {
  const template = kind?.template || 'default'
  const icon = kind?.icon || '•'

  // Photo template hooks - MUST be at top level, always called regardless of template
  const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0)
  const [viewerOpen, setViewerOpen] = useState(false)
  const [captionExpanded, setCaptionExpanded] = useState(false)

  // Reactions, bookmarks, and edit history state
  const [reactions, setReactions] = useState<ReactionSummary | null>(null)
  const [isBookmarked, setIsBookmarked] = useState(false)
  const [showHistoryModal, setShowHistoryModal] = useState(false)

  // Fetch reactions and bookmark status on mount
  useEffect(() => {
    const fetchReactionsAndBookmark = async () => {
      try {
        // Fetch reactions
        const reactionsResp = await fetch(apiUrl(`/api/things/${thing.id}/reactions`), { credentials: 'include' })
        if (reactionsResp.ok) {
          const data = await reactionsResp.json()
          setReactions(data.data)
        }

        // Fetch bookmark status
        const bookmarkResp = await fetch(apiUrl(`/api/things/${thing.id}/bookmark`), { credentials: 'include' })
        if (bookmarkResp.ok) {
          const data = await bookmarkResp.json()
          setIsBookmarked(data.data?.bookmarked || false)
        }
      } catch (e) {
        console.error('Failed to fetch reactions/bookmark:', e)
      }
    }
    fetchReactionsAndBookmark()
  }, [thing.id])

  // Photo Viewer Modal - keyboard navigation
  useEffect(() => {
    if (!viewerOpen || template !== 'photo' || !thing.photos) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setViewerOpen(false)
      } else if (e.key === 'ArrowLeft') {
        setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1))
      } else if (e.key === 'ArrowRight') {
        setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1))
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [viewerOpen, thing.photos, template])

  // Delete button (shared across templates)
  const DeleteButton = () => (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onDelete()
      }}
      className="bg-transparent border-none cursor-pointer text-lg px-2 py-1 flex-shrink-0"
      style={{ color: theme.textDisabled }}
      onMouseEnter={e => (e.currentTarget.style.color = theme.error)}
      onMouseLeave={e => (e.currentTarget.style.color = theme.textDisabled)}
    >
      ×
    </button>
  )

  // Edit button (shared across templates)
  const EditButton = () => (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onEdit()
      }}
      className="bg-transparent border-none cursor-pointer text-sm px-2 py-1 flex-shrink-0"
      style={{ color: theme.textDisabled }}
      onMouseEnter={e => (e.currentTarget.style.color = theme.accent)}
      onMouseLeave={e => (e.currentTarget.style.color = theme.textDisabled)}
      title="Edit"
    >
      ✎
    </button>
  )

  // Navigate to post detail page
  const handleCardClick = () => {
    if (!isDetailView) {
      // Save scroll position before navigating
      sessionStorage.setItem('feedScrollPosition', String(window.scrollY))
      navigateTo(`/post/${thing.id}`)
    }
  }

  // Attributes display (shared across templates)
  const AttributesDisplay = ({ compact = false }: { compact?: boolean }) => {
    if (!kind?.attributes || Object.keys(thing.metadata || {}).length === 0) return null
    return (
      <div className="flex flex-wrap" style={{ gap: compact ? 4 : 8, marginTop: compact ? 4 : 8 }}>
        {kind.attributes.map(attr => {
          const val = thing.metadata?.[attr.name]
          if (val === undefined || val === null || val === '') return null

          // Handle link type attributes - skip them here, they're shown separately
          if (attr.type === 'link') return null

          return (
            <span
              key={attr.name}
              className="rounded"
              style={{
                fontSize: compact ? 11 : 12,
                padding: compact ? '1px 6px' : '2px 8px',
                background: theme.bgMuted,
                color: theme.textMuted,
              }}
            >
              {attr.type === 'checkbox' ? (val ? '✓ ' : '○ ') : ''}
              {attr.type === 'url' ? (
                <a
                  href={String(val)}
                  target="_blank"
                  onClick={e => e.stopPropagation()}
                  className="no-underline"
                  style={{ color: theme.link }}
                >
                  {attr.name}
                </a>
              ) : (
                <>{attr.name}: {attr.type === 'checkbox' ? (val ? 'Yes' : 'No') : String(val)}</>
              )}
            </span>
          )
        })}
      </div>
    )
  }

  // Display linked Things
  const LinkedThingsDisplay = () => {
    if (!kind?.attributes) return null
    const linkAttrs = kind.attributes.filter(a => a.type === 'link')
    if (linkAttrs.length === 0) return null

    const linkedThingIds = new Set<string>()
    linkAttrs.forEach(attr => {
      const val = thing.metadata?.[attr.name]
      if (Array.isArray(val)) {
        val.forEach((id: string) => linkedThingIds.add(id))
      }
    })

    if (linkedThingIds.size === 0) return null

    return (
      <div className="mt-3">
        <div className="text-xs font-medium mb-1.5" style={{ color: theme.textMuted }}>
          Linked Things
        </div>
        <div className="flex flex-wrap gap-1.5">
          {Array.from(linkedThingIds).map(linkedId => (
            <div
              key={linkedId}
              onClick={(e) => {
                e.stopPropagation()
                navigateTo(`/post/${linkedId}`)
              }}
              className="px-2.5 py-1 rounded text-xs cursor-pointer transition-opacity"
              style={{
                background: theme.link,
                color: theme.bgCard,
              }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.8')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              {linkedId.slice(0, 8)}...
            </div>
          ))}
        </div>
      </div>
    )
  }

  // COMPACT template - minimal one-line display
  if (template === 'compact') {
    return (
      <div
        onClick={handleCardClick}
        className="flex items-center gap-2.5 px-3.5 py-2.5 rounded-md border cursor-pointer transition-colors"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
        }}
        onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
        onMouseLeave={e => (e.currentTarget.style.background = theme.bgCard)}
      >
        <span className="text-base">{icon}</span>
        <span className="flex-1 text-sm overflow-hidden text-ellipsis whitespace-nowrap" style={{ color: theme.text }}>
          {thing.content}
        </span>
        <span className="text-xs flex-shrink-0" style={{ color: theme.textSubtle }}>
          {new Date(thing.created_at).toLocaleDateString()}
        </span>
        <EditButton />
      </div>
    )
  }

  // CHECKLIST template - task-style with checkbox
  if (template === 'checklist') {
    const isDone = Boolean(thing.metadata?.done)
    return (
      <div
        className="flex items-start gap-3 px-3.5 py-3 rounded-lg border cursor-pointer transition-colors"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
        }}
        onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
        onMouseLeave={e => (e.currentTarget.style.background = theme.bgCard)}
      >
        <input
          type="checkbox"
          checked={isDone}
          onChange={(e) => {
            e.stopPropagation()
            onUpdateThing({ ...thing, metadata: { ...thing.metadata, done: !isDone } })
          }}
          className="w-4.5 h-4.5 mt-0.5 cursor-pointer"
          style={{ accentColor: theme.accent }}
        />
        <div className="flex-1" onClick={handleCardClick}>
          <span
            className="text-sm"
            style={{
              textDecoration: isDone ? 'line-through' : 'none',
              color: isDone ? theme.textSubtle : theme.text,
            }}
          >
            {thing.content}
          </span>
          <AttributesDisplay compact />
        </div>
        <span className="text-xs flex-shrink-0" style={{ color: theme.textSubtle }}>
          {new Date(thing.created_at).toLocaleDateString()}
        </span>
        <EditButton />
      </div>
    )
  }

  // LINK template - URL-focused
  if (template === 'link') {
    const url = thing.metadata?.url as string | undefined
    return (
      <div
        onClick={handleCardClick}
        className="p-3.5 rounded-lg border cursor-pointer transition-shadow"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
          borderLeft: `4px solid ${theme.accent}`,
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-base">{icon}</span>
              <span className="text-sm font-medium" style={{ color: theme.text }}>{thing.content}</span>
            </div>
            {url && (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="text-xs block overflow-hidden text-ellipsis whitespace-nowrap max-w-full no-underline"
                style={{ color: theme.link }}
              >
                {url}
              </a>
            )}
            <div className="text-xs mt-1.5" style={{ color: theme.textSubtle }}>
              {new Date(thing.created_at).toLocaleDateString()}
            </div>
          </div>
          <EditButton />
        </div>
      </div>
    )
  }

  // CARD template - rich card with prominent content
  if (template === 'card') {
    return (
      <div
        onClick={handleCardClick}
        className="rounded-xl border overflow-hidden cursor-pointer transition-shadow"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div className="px-4 py-3 flex items-center gap-2" style={{ background: theme.bgHover }}>
          <span className="text-xl">{icon}</span>
          <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: theme.textMuted }}>
            {thing.type}
          </span>
          <div className="flex-1" />
          <EditButton />
        </div>
        <div className="p-4">
          <Markdown content={thing.content} theme={theme} className="markdown-content" />
          <AttributesDisplay />
          <p className="text-xs mt-3 m-0" style={{ color: theme.textSubtle }}>
            {new Date(thing.created_at).toLocaleString()}
          </p>
        </div>
      </div>
    )
  }

  // PHOTO template - image/video display
  if (template === 'photo') {
    // Handle gallery with multiple photos
    if (thing.photos && thing.photos.length > 0) {
      const currentPhoto = thing.photos[currentPhotoIndex]
      const isVideo = currentPhoto.content_type?.startsWith('video/')

      const PhotoViewer = () => {
        if (!viewerOpen) return null
        return (
          <div
            onClick={() => setViewerOpen(false)}
            className="fixed inset-0 flex flex-col cursor-zoom-out"
            style={{
              background: 'rgba(0, 0, 0, 0.95)',
              zIndex: 10000,
            }}
          >
            {/* Close button */}
            <button
              onClick={() => setViewerOpen(false)}
              className="absolute top-4 right-4 border-none text-white text-2xl px-4 py-2 rounded-lg cursor-pointer"
              style={{
                background: 'rgba(255, 255, 255, 0.1)',
                zIndex: 10001,
              }}
            >
              ×
            </button>

            {/* Photo area - takes remaining space */}
            <div className="flex-1 flex items-center justify-center relative min-h-0">
              {/* Navigation arrows */}
              {thing.photos!.length > 1 && (
                <>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                    className="absolute left-4 top-1/2 -translate-y-1/2 text-white border-none px-6 py-4 rounded-lg cursor-pointer text-2xl"
                    style={{
                      background: 'rgba(255, 255, 255, 0.1)',
                      zIndex: 10001,
                    }}
                  >
                    ‹
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-white border-none px-6 py-4 rounded-lg cursor-pointer text-2xl"
                    style={{
                      background: 'rgba(255, 255, 255, 0.1)',
                      zIndex: 10001,
                    }}
                  >
                    ›
                  </button>
                </>
              )}

              {/* Full-size image */}
              <div onClick={(e) => e.stopPropagation()} className="max-w-full max-h-full cursor-default relative">
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    autoPlay
                    className="max-w-screen max-h-[60vh] object-contain"
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    className="max-w-screen max-h-[60vh] object-contain"
                  />
                )}
                {thing.photos!.length > 1 && (
                  <p className="text-center mt-2 text-xs" style={{ color: 'rgba(255,255,255,0.6)' }}>
                    {currentPhotoIndex + 1} / {thing.photos!.length}
                  </p>
                )}
              </div>
            </div>

            {/* Bottom section - caption and comments stub */}
            <div
              onClick={(e) => e.stopPropagation()}
              className="p-4 cursor-default max-h-[40vh] overflow-y-auto"
              style={{
                background: theme.bgCard,
                borderTop: `1px solid ${theme.border}`,
              }}
            >
              {/* Caption */}
              {currentPhoto.caption && (
                <div
                  onClick={(e) => { e.stopPropagation(); setCaptionExpanded(!captionExpanded) }}
                  className="text-sm mb-3 cursor-pointer"
                  style={{
                    color: theme.text,
                    ...(captionExpanded ? {} : {
                      maxHeight: '4.5em',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      display: '-webkit-box',
                      WebkitLineClamp: 3,
                      WebkitBoxOrient: 'vertical',
                    })
                  }}
                >
                  {currentPhoto.caption}
                </div>
              )}

              {/* Post content */}
              {thing.content && (
                <div className="text-sm mb-3 pb-3" style={{ color: theme.text, borderBottom: `1px solid ${theme.border}` }}>
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}

              {/* Replies link */}
              <div className="text-xs pt-2" style={{ color: theme.textMuted }}>
                <a
                  href={`/post/${thing.id}`}
                  onClick={(e) => { e.stopPropagation(); navigateTo(`/post/${thing.id}`) }}
                  className="no-underline"
                  style={{ color: theme.accent }}
                >
                  View replies →
                </a>
              </div>
            </div>
          </div>
        )
      }

      // Two-column layout for desktop detail view
      // Two-column layout for photo viewer modal
      if (viewerOpen && window.innerWidth > 768) {
        return (
          <>
            {/* Modal backdrop */}
            <div
              onClick={() => setViewerOpen(false)}
              className="fixed inset-0 flex items-center justify-center p-10"
              style={{
                background: 'rgba(0, 0, 0, 0.9)',
                zIndex: 9999,
              }}
            >
              <div
                onClick={(e) => e.stopPropagation()}
                className="grid gap-0 rounded-xl border overflow-hidden max-w-[1400px] max-h-[90vh] w-full"
                style={{
                  gridTemplateColumns: '1fr 400px',
                  background: theme.bgCard,
                  borderColor: theme.border,
                }}
              >
              {/* Left column: Photo gallery (sticky) */}
              <div className="relative bg-black flex items-center justify-center min-h-[500px] max-h-[80vh]">
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    className="max-w-full max-h-[80vh] w-auto h-auto object-contain block"
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    className="max-w-full max-h-[80vh] w-auto h-auto object-contain block"
                  />
                )}

                {/* Carousel Navigation */}
                {thing.photos!.length > 1 && (
                  <>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                      className="absolute left-4 top-1/2 -translate-y-1/2 text-white border-none px-5 py-3 rounded-lg cursor-pointer text-2xl"
                      style={{ background: 'rgba(0, 0, 0, 0.5)' }}
                    >
                      ‹
                    </button>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-white border-none px-5 py-3 rounded-lg cursor-pointer text-2xl"
                      style={{ background: 'rgba(0, 0, 0, 0.5)' }}
                    >
                      ›
                    </button>
                    <div
                      className="absolute left-1/2 -translate-x-1/2 text-white px-3 py-1.5 rounded-md text-xs"
                      style={{
                        bottom: currentPhoto.caption ? 56 : 16,
                        background: 'rgba(0, 0, 0, 0.7)',
                      }}
                    >
                      {currentPhotoIndex + 1} / {thing.photos.length}
                    </div>
                  </>
                )}

                {/* Photo caption at bottom */}
                {currentPhoto.caption && (
                  <div
                    className="absolute bottom-0 left-0 right-0 text-white px-4 py-3 text-sm"
                    style={{ background: 'rgba(0, 0, 0, 0.8)' }}
                  >
                    {currentPhoto.caption}
                  </div>
                )}
              </div>

              {/* Right column: Content */}
              <div className="p-5 flex flex-col gap-4">
                {/* Header with icon and delete button */}
                <div className="flex justify-between items-start">
                  <div className="flex items-center gap-2">
                    <span className="text-xl">{icon}</span>
                    <span className="text-xs" style={{ color: theme.textMuted }}>{kind?.name || 'Photo'}</span>
                  </div>
                  <div className="flex gap-1">
                    <EditButton />
                    <DeleteButton />
                  </div>
                </div>

                {/* Post content */}
                {thing.content && (
                  <div className="pb-3" style={{ borderBottom: `1px solid ${theme.border}` }}>
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}

                {/* Metadata */}
                <div className="mt-auto">
                  <p className="text-xs m-0" style={{ color: theme.textSubtle }}>
                    {new Date(thing.created_at).toLocaleString()}
                  </p>
                </div>
              </div>
              </div>
            </div>
          </>
        )
      }

      // Single-column layout (feed view or mobile)
      return (
        <div
          onClick={handleCardClick}
          className="rounded-xl border overflow-hidden cursor-pointer transition-shadow"
          style={{
            background: theme.bgCard,
            borderColor: theme.border,
          }}
          onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
        >
          <PhotoViewer />
          {/* Photo/Video Display */}
          <div className="relative bg-black">
            {isVideo ? (
              <video
                src={apiUrl(`/api/photos/${currentPhoto.id}?size=thumb`)}
                controls
                className="w-full max-h-[400px] object-contain block"
                onClick={(e) => {
                  e.stopPropagation()
                  if (isDetailView) setViewerOpen(true)
                  else handleCardClick()
                }}
              />
            ) : (
              <img
                src={apiUrl(`/api/photos/${currentPhoto.id}?size=thumb`)}
                alt={currentPhoto.caption || 'Photo'}
                onClick={(e) => {
                  e.stopPropagation()
                  if (isDetailView) setViewerOpen(true)
                  else handleCardClick()
                }}
                className="w-full max-h-[400px] object-contain block"
                style={{ cursor: isDetailView ? 'zoom-in' : 'pointer' }}
              />
            )}

            {/* Carousel Navigation */}
            {thing.photos!.length > 1 && (
              <>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                  className="absolute left-2 top-1/2 -translate-y-1/2 text-white border-none px-3 py-2 rounded cursor-pointer text-lg"
                  style={{ background: 'rgba(0, 0, 0, 0.5)' }}
                >
                  ‹
                </button>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-white border-none px-3 py-2 rounded cursor-pointer text-lg"
                  style={{ background: 'rgba(0, 0, 0, 0.5)' }}
                >
                  ›
                </button>
                <div
                  className="absolute bottom-2 right-2 text-white px-2 py-1 rounded text-xs"
                  style={{ background: 'rgba(0, 0, 0, 0.7)' }}
                >
                  {currentPhotoIndex + 1} / {thing.photos.length}
                </div>
              </>
            )}
          </div>

          <div className="p-3">
            <div className="flex justify-between items-start">
              <div className="flex-1">
                {currentPhoto.caption && (
                  <p className="m-0 mb-2 text-xs" style={{ color: theme.text }}>
                    {currentPhoto.caption}
                  </p>
                )}
                {thing.content && (
                  <div onClick={handleCardClick} className="cursor-pointer mb-2">
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}
                <p className="text-xs m-0" style={{ color: theme.textSubtle }}>
                  {new Date(thing.created_at).toLocaleString()}
                </p>
              </div>
              <EditButton />
            </div>
          </div>
        </div>
      )
    }

    // Handle single photo (metadata.url)
    const url = thing.metadata?.url as string | undefined
    const contentType = thing.metadata?.content_type as string | undefined
    const isVideo = contentType?.startsWith('video/')

    return (
      <div
        onClick={handleCardClick}
        className="rounded-xl border overflow-hidden cursor-pointer transition-shadow"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        {url && (
          isVideo ? (
            <video
              src={url}
              controls
              className="w-full max-h-[400px] object-contain bg-black"
            />
          ) : (
            <img
              src={url}
              alt={thing.content || 'Photo'}
              className="w-full max-h-[400px] object-contain cursor-pointer"
              style={{ background: theme.bgHover }}
              onClick={() => window.open(url, '_blank')}
            />
          )
        )}
        <div className="p-3">
          <div className="flex justify-between items-start">
            <div className="flex-1">
              {thing.content && (
                <div onClick={handleCardClick} className="cursor-pointer">
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}
              <p className="text-xs m-0" style={{ color: theme.textSubtle, marginTop: thing.content ? 8 : 0 }}>
                {new Date(thing.created_at).toLocaleString()}
              </p>
            </div>
            <EditButton />
          </div>
        </div>
      </div>
    )
  }

  // DEFAULT template - standard card
  return (
    <>
      <div
        onClick={handleCardClick}
        className="p-4 rounded-lg border cursor-pointer transition-shadow"
        style={{
          background: theme.bgCard,
          borderColor: theme.border,
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <span
              className="inline-block px-2.5 py-0.5 rounded text-xs font-medium mb-2"
              style={{
                background: theme.bgMuted,
                color: theme.textMuted,
              }}
            >
              {icon} {thing.type}
            </span>
            <Markdown content={thing.content} theme={theme} className="markdown-content" />
            <AttributesDisplay />
            <LinkedThingsDisplay />
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs" style={{ color: theme.textSubtle }}>
                {new Date(thing.created_at).toLocaleString()}
              </span>
              {thing.edited_at && (
                <EditedIndicator
                  editedAt={thing.edited_at}
                  onClick={() => setShowHistoryModal(true)}
                  theme={theme}
                />
              )}
            </div>
            {/* Reactions - only show if kind is reactable (defaults to true for backwards compatibility) */}
            {kind?.reactable !== false && (
              <div className="mt-3" onClick={e => e.stopPropagation()}>
                <ReactionBar
                  targetId={thing.id}
                  targetType="thing"
                  reactions={reactions}
                  onReactionsChange={setReactions}
                  theme={theme}
                />
              </div>
            )}
          </div>
          <div className="flex items-center">
            <BookmarkButton
              thingId={thing.id}
              isBookmarked={isBookmarked}
              onBookmarkChange={setIsBookmarked}
              theme={theme}
            />
            <EditButton />
          </div>
        </div>
      </div>

      {/* Edit History Modal */}
      {showHistoryModal && (
        <EditHistoryModal
          targetId={thing.id}
          targetType="thing"
          onClose={() => setShowHistoryModal(false)}
          theme={theme}
        />
      )}
    </>
  )
}


