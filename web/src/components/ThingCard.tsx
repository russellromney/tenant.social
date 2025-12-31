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
      style={{
        background: 'none',
        border: 'none',
        color: theme.textDisabled,
        cursor: 'pointer',
        fontSize: 18,
        padding: '4px 8px',
        flexShrink: 0,
      }}
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
      style={{
        background: 'none',
        border: 'none',
        color: theme.textDisabled,
        cursor: 'pointer',
        fontSize: 14,
        padding: '4px 8px',
        flexShrink: 0,
      }}
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
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: compact ? 4 : 8, marginTop: compact ? 4 : 8 }}>
        {kind.attributes.map(attr => {
          const val = thing.metadata?.[attr.name]
          if (val === undefined || val === null || val === '') return null

          // Handle link type attributes - skip them here, they're shown separately
          if (attr.type === 'link') return null

          return (
            <span
              key={attr.name}
              style={{
                fontSize: compact ? 11 : 12,
                padding: compact ? '1px 6px' : '2px 8px',
                background: theme.bgMuted,
                borderRadius: 4,
                color: theme.textMuted,
              }}
            >
              {attr.type === 'checkbox' ? (val ? '✓ ' : '○ ') : ''}
              {attr.type === 'url' ? (
                <a
                  href={String(val)}
                  target="_blank"
                  onClick={e => e.stopPropagation()}
                  style={{ color: theme.link, textDecoration: 'none' }}
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
      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 12, color: theme.textMuted, marginBottom: 6, fontWeight: 500 }}>
          Linked Things
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {Array.from(linkedThingIds).map(linkedId => (
            <div
              key={linkedId}
              onClick={(e) => {
                e.stopPropagation()
                navigateTo(`/post/${linkedId}`)
              }}
              style={{
                padding: '4px 10px',
                background: theme.link,
                color: theme.bgCard,
                borderRadius: 4,
                fontSize: 12,
                cursor: 'pointer',
                transition: 'opacity 0.15s',
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
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '10px 14px',
          background: theme.bgCard,
          borderRadius: 6,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
        onMouseLeave={e => (e.currentTarget.style.background = theme.bgCard)}
      >
        <span style={{ fontSize: 16 }}>{icon}</span>
        <span style={{ flex: 1, fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: theme.text }}>
          {thing.content}
        </span>
        <span style={{ fontSize: 11, color: theme.textSubtle, flexShrink: 0 }}>
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
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
          padding: '12px 14px',
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'background 0.15s',
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
          style={{ width: 18, height: 18, marginTop: 2, cursor: 'pointer', accentColor: theme.accent }}
        />
        <div style={{ flex: 1 }} onClick={handleCardClick}>
          <span
            style={{
              fontSize: 15,
              textDecoration: isDone ? 'line-through' : 'none',
              color: isDone ? theme.textSubtle : theme.text,
            }}
          >
            {thing.content}
          </span>
          <AttributesDisplay compact />
        </div>
        <span style={{ fontSize: 11, color: theme.textSubtle, flexShrink: 0 }}>
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
        style={{
          padding: 14,
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          borderLeft: `4px solid ${theme.accent}`,
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 16 }}>{icon}</span>
              <span style={{ fontSize: 15, fontWeight: 500, color: theme.text }}>{thing.content}</span>
            </div>
            {url && (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                style={{
                  fontSize: 13,
                  color: theme.link,
                  textDecoration: 'none',
                  display: 'block',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '100%',
                }}
              >
                {url}
              </a>
            )}
            <div style={{ fontSize: 11, color: theme.textSubtle, marginTop: 6 }}>
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
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ background: theme.bgHover, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 20 }}>{icon}</span>
          <span style={{ fontSize: 12, fontWeight: 600, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            {thing.type}
          </span>
          <div style={{ flex: 1 }} />
          <EditButton />
        </div>
        <div style={{ padding: 16 }}>
          <Markdown content={thing.content} theme={theme} className="markdown-content" />
          <AttributesDisplay />
          <p style={{ fontSize: 12, color: theme.textSubtle, margin: '12px 0 0' }}>
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
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0, 0, 0, 0.95)',
              zIndex: 10000,
              display: 'flex',
              flexDirection: 'column',
              cursor: 'zoom-out',
            }}
          >
            {/* Close button */}
            <button
              onClick={() => setViewerOpen(false)}
              style={{
                position: 'absolute',
                top: 16,
                right: 16,
                background: 'rgba(255, 255, 255, 0.1)',
                border: 'none',
                color: '#fff',
                fontSize: 24,
                padding: '8px 16px',
                borderRadius: 8,
                cursor: 'pointer',
                zIndex: 10001,
              }}
            >
              ×
            </button>

            {/* Photo area - takes remaining space */}
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', minHeight: 0 }}>
              {/* Navigation arrows */}
              {thing.photos!.length > 1 && (
                <>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                    style={{
                      position: 'absolute',
                      left: 16,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'rgba(255, 255, 255, 0.1)',
                      color: '#fff',
                      border: 'none',
                      padding: '16px 24px',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontSize: 24,
                      zIndex: 10001,
                    }}
                  >
                    ‹
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                    style={{
                      position: 'absolute',
                      right: 16,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'rgba(255, 255, 255, 0.1)',
                      color: '#fff',
                      border: 'none',
                      padding: '16px 24px',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontSize: 24,
                      zIndex: 10001,
                    }}
                  >
                    ›
                  </button>
                </>
              )}

              {/* Full-size image */}
              <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: '100%', maxHeight: '100%', cursor: 'default', position: 'relative' }}>
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    autoPlay
                    style={{ maxWidth: '100vw', maxHeight: '60vh', objectFit: 'contain' }}
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    style={{ maxWidth: '100vw', maxHeight: '60vh', objectFit: 'contain' }}
                  />
                )}
                {thing.photos!.length > 1 && (
                  <p style={{ color: 'rgba(255,255,255,0.6)', textAlign: 'center', marginTop: 8, fontSize: 12 }}>
                    {currentPhotoIndex + 1} / {thing.photos!.length}
                  </p>
                )}
              </div>
            </div>

            {/* Bottom section - caption and comments stub */}
            <div
              onClick={(e) => e.stopPropagation()}
              style={{
                background: theme.bgCard,
                borderTop: `1px solid ${theme.border}`,
                padding: 16,
                cursor: 'default',
                maxHeight: '40vh',
                overflowY: 'auto',
              }}
            >
              {/* Caption */}
              {currentPhoto.caption && (
                <div
                  onClick={(e) => { e.stopPropagation(); setCaptionExpanded(!captionExpanded) }}
                  style={{
                    color: theme.text,
                    fontSize: 14,
                    marginBottom: 12,
                    cursor: 'pointer',
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
                <div style={{ color: theme.text, fontSize: 14, marginBottom: 12, paddingBottom: 12, borderBottom: `1px solid ${theme.border}` }}>
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}

              {/* Replies link */}
              <div style={{ color: theme.textMuted, fontSize: 13, paddingTop: 8 }}>
                <a
                  href={`/post/${thing.id}`}
                  onClick={(e) => { e.stopPropagation(); navigateTo(`/post/${thing.id}`) }}
                  style={{ color: theme.accent, textDecoration: 'none' }}
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
              style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.9)',
                zIndex: 9999,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: 40,
              }}
            >
              <div
                onClick={(e) => e.stopPropagation()}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 400px',
                  gap: 0,
                  background: theme.bgCard,
                  borderRadius: 12,
                  border: `1px solid ${theme.border}`,
                  overflow: 'hidden',
                  maxWidth: 1400,
                  maxHeight: '90vh',
                  width: '100%',
                }}
              >
              {/* Left column: Photo gallery (sticky) */}
              <div style={{ position: 'relative', background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 500, maxHeight: '80vh' }}>
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    style={{
                      maxWidth: '100%',
                      maxHeight: '80vh',
                      width: 'auto',
                      height: 'auto',
                      objectFit: 'contain',
                      display: 'block',
                    }}
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    style={{
                      maxWidth: '100%',
                      maxHeight: '80vh',
                      width: 'auto',
                      height: 'auto',
                      objectFit: 'contain',
                      display: 'block',
                    }}
                  />
                )}

                {/* Carousel Navigation */}
                {thing.photos!.length > 1 && (
                  <>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                      style={{
                        position: 'absolute',
                        left: 16,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'rgba(0, 0, 0, 0.5)',
                        color: '#fff',
                        border: 'none',
                        padding: '12px 20px',
                        borderRadius: 8,
                        cursor: 'pointer',
                        fontSize: 24,
                      }}
                    >
                      ‹
                    </button>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                      style={{
                        position: 'absolute',
                        right: 16,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'rgba(0, 0, 0, 0.5)',
                        color: '#fff',
                        border: 'none',
                        padding: '12px 20px',
                        borderRadius: 8,
                        cursor: 'pointer',
                        fontSize: 24,
                      }}
                    >
                      ›
                    </button>
                    <div
                      style={{
                        position: 'absolute',
                        bottom: currentPhoto.caption ? 56 : 16,
                        left: '50%',
                        transform: 'translateX(-50%)',
                        background: 'rgba(0, 0, 0, 0.7)',
                        color: '#fff',
                        padding: '6px 12px',
                        borderRadius: 6,
                        fontSize: 13,
                      }}
                    >
                      {currentPhotoIndex + 1} / {thing.photos.length}
                    </div>
                  </>
                )}

                {/* Photo caption at bottom */}
                {currentPhoto.caption && (
                  <div
                    style={{
                      position: 'absolute',
                      bottom: 0,
                      left: 0,
                      right: 0,
                      background: 'rgba(0, 0, 0, 0.8)',
                      color: '#fff',
                      padding: '12px 16px',
                      fontSize: 14,
                    }}
                  >
                    {currentPhoto.caption}
                  </div>
                )}
              </div>

              {/* Right column: Content */}
              <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Header with icon and delete button */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 20 }}>{icon}</span>
                    <span style={{ fontSize: 13, color: theme.textMuted }}>{kind?.name || 'Photo'}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <EditButton />
                    <DeleteButton />
                  </div>
                </div>

                {/* Post content */}
                {thing.content && (
                  <div style={{ paddingBottom: 12, borderBottom: `1px solid ${theme.border}` }}>
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}

                {/* Metadata */}
                <div style={{ marginTop: 'auto' }}>
                  <p style={{ fontSize: 11, color: theme.textSubtle, margin: 0 }}>
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
          style={{
            background: theme.bgCard,
            borderRadius: 12,
            border: `1px solid ${theme.border}`,
            overflow: 'hidden',
            cursor: 'pointer',
            transition: 'box-shadow 0.15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
        >
          <PhotoViewer />
          {/* Photo/Video Display */}
          <div style={{ position: 'relative', background: '#000' }}>
            {isVideo ? (
              <video
                src={apiUrl(`/api/photos/${currentPhoto.id}?size=thumb`)}
                controls
                style={{
                  width: '100%',
                  maxHeight: 400,
                  objectFit: 'contain',
                  display: 'block',
                }}
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
                style={{
                  width: '100%',
                  maxHeight: 400,
                  objectFit: 'contain',
                  display: 'block',
                  cursor: isDetailView ? 'zoom-in' : 'pointer',
                }}
              />
            )}

            {/* Carousel Navigation */}
            {thing.photos!.length > 1 && (
              <>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                  style={{
                    position: 'absolute',
                    left: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'rgba(0, 0, 0, 0.5)',
                    color: '#fff',
                    border: 'none',
                    padding: '8px 12px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 18,
                  }}
                >
                  ‹
                </button>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                  style={{
                    position: 'absolute',
                    right: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'rgba(0, 0, 0, 0.5)',
                    color: '#fff',
                    border: 'none',
                    padding: '8px 12px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 18,
                  }}
                >
                  ›
                </button>
                <div
                  style={{
                    position: 'absolute',
                    bottom: 8,
                    right: 8,
                    background: 'rgba(0, 0, 0, 0.7)',
                    color: '#fff',
                    padding: '4px 8px',
                    borderRadius: 4,
                    fontSize: 12,
                  }}
                >
                  {currentPhotoIndex + 1} / {thing.photos.length}
                </div>
              </>
            )}
          </div>

          <div style={{ padding: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
              <div style={{ flex: 1 }}>
                {currentPhoto.caption && (
                  <p style={{ margin: '0 0 8px 0', fontSize: 13, color: theme.text }}>
                    {currentPhoto.caption}
                  </p>
                )}
                {thing.content && (
                  <div onClick={handleCardClick} style={{ cursor: 'pointer', marginBottom: 8 }}>
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}
                <p style={{ fontSize: 11, color: theme.textSubtle, margin: 0 }}>
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
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        {url && (
          isVideo ? (
            <video
              src={url}
              controls
              style={{
                width: '100%',
                maxHeight: 400,
                objectFit: 'contain',
                background: '#000',
              }}
            />
          ) : (
            <img
              src={url}
              alt={thing.content || 'Photo'}
              style={{
                width: '100%',
                maxHeight: 400,
                objectFit: 'contain',
                background: theme.bgHover,
                cursor: 'pointer',
              }}
              onClick={() => window.open(url, '_blank')}
            />
          )
        )}
        <div style={{ padding: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div style={{ flex: 1 }}>
              {thing.content && (
                <div onClick={handleCardClick} style={{ cursor: 'pointer' }}>
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}
              <p style={{ fontSize: 11, color: theme.textSubtle, margin: thing.content ? '8px 0 0' : 0 }}>
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
        style={{
          padding: 16,
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div style={{ flex: 1 }}>
            <span
              style={{
                display: 'inline-block',
                padding: '3px 10px',
                background: theme.bgMuted,
                color: theme.textMuted,
                borderRadius: 4,
                fontSize: 12,
                fontWeight: 500,
                marginBottom: 8,
              }}
            >
              {icon} {thing.type}
            </span>
            <Markdown content={thing.content} theme={theme} className="markdown-content" />
            <AttributesDisplay />
            <LinkedThingsDisplay />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
              <span style={{ fontSize: 12, color: theme.textSubtle }}>
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
              <div style={{ marginTop: 12 }} onClick={e => e.stopPropagation()}>
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
          <div style={{ display: 'flex', alignItems: 'center' }}>
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


