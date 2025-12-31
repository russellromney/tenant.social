import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Comment, ReactionSummary } from '../types'
import { apiUrl, routeHref } from '../api'
import { ReactionBar, EditedIndicator, EditHistoryModal, formatTimeAgo } from './index'

interface CommentTreeNode {
  comment: Comment
  replies: CommentTreeNode[]
}

function buildCommentTree(comments: Comment[]): CommentTreeNode[] {
  const nodeMap = new Map<string, CommentTreeNode>()
  const rootNodes: CommentTreeNode[] = []

  // Create nodes for all comments
  comments.forEach(comment => {
    nodeMap.set(comment.id, { comment, replies: [] })
  })

  // Build tree structure
  comments.forEach(comment => {
    const node = nodeMap.get(comment.id)!
    const parentId = comment.metadata.parent_id
    const rootId = comment.metadata.root_id

    // If parent_id equals root_id, this is a top-level comment
    if (parentId === rootId) {
      rootNodes.push(node)
    } else {
      // This is a reply - find parent and add to its replies
      const parentNode = nodeMap.get(parentId)
      if (parentNode) {
        parentNode.replies.push(node)
      } else {
        // Parent not found (maybe deleted?), treat as root
        rootNodes.push(node)
      }
    }
  })

  // Sort by created_at
  const sortByDate = (a: CommentTreeNode, b: CommentTreeNode) =>
    new Date(a.comment.created_at).getTime() - new Date(b.comment.created_at).getTime()

  rootNodes.sort(sortByDate)
  const sortReplies = (nodes: CommentTreeNode[]) => {
    nodes.sort(sortByDate)
    nodes.forEach(n => sortReplies(n.replies))
  }
  sortReplies(rootNodes)

  return rootNodes
}

// Count total descendants in a comment tree
function countDescendants(node: CommentTreeNode): number {
  let count = node.replies.length
  for (const reply of node.replies) {
    count += countDescendants(reply)
  }
  return count
}

function CommentItem({
  node,
  thingId,
  currentUserId,
  thingOwnerId,
  theme,
  onReply,
  onDelete,
  replyingTo,
  setReplyingTo,
  replyContent,
  setReplyContent,
  submittingReply,
  totalComments = 0,
  commentable = true,
}: {
  node: CommentTreeNode
  thingId: string
  currentUserId: string | null
  thingOwnerId: string | null
  theme: Theme
  onReply: (parentId: string, content: string) => Promise<void>
  onDelete: (commentId: string) => Promise<void>
  replyingTo: string | null
  setReplyingTo: (id: string | null) => void
  replyContent: string
  setReplyContent: (content: string) => void
  submittingReply: boolean
  totalComments?: number
  commentable?: boolean
}) {
  const { comment, replies } = node
  const depth = comment.metadata.depth
  const isDeleted = !!comment.deleted_at
  const canDelete = currentUserId && (comment.user_id === currentUserId || thingOwnerId === currentUserId)
  const canReply = commentable && depth < 3 && !isDeleted && currentUserId
  const isReplyingToThis = replyingTo === comment.id
  const totalDescendants = countDescendants(node)

  // Auto-collapse: depth 3+ when thread has >10 total comments
  const shouldAutoCollapse = depth >= 2 && totalComments > 10
  const [expanded, setExpanded] = useState(!shouldAutoCollapse)
  const [deleting, setDeleting] = useState(false)
  const [reactions, setReactions] = useState<ReactionSummary | null>(null)
  const [showHistoryModal, setShowHistoryModal] = useState(false)

  // Fetch reactions for this comment
  useEffect(() => {
    if (isDeleted) return
    fetch(apiUrl(`/api/comments/${comment.id}/reactions`), { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => data && setReactions(data.data))
      .catch(() => {})
  }, [comment.id, isDeleted])

  // Get display name from author info, fallback to user_id
  const authorName = isDeleted
    ? '[deleted]'
    : comment.author?.display_name || comment.user_id || 'Anonymous'

  const parentAuthorName = comment.parent_author?.display_name || 'Unknown'

  const handleDelete = async () => {
    if (!confirm('Delete this reply?')) return
    setDeleting(true)
    try {
      await onDelete(comment.id)
    } finally {
      setDeleting(false)
    }
  }

  const handleSubmitReply = async () => {
    if (!replyContent.trim()) return
    await onReply(comment.id, replyContent)
  }

  // Collapsed view
  if (!expanded && replies.length > 0) {
    return (
      <div style={{ marginLeft: depth > 0 ? 24 : 0 }}>
        <div
          onClick={() => setExpanded(true)}
          style={{
            padding: '8px 12px',
            margin: '4px 0',
            background: theme.bgCard,
            border: `1px solid ${theme.border}`,
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 13,
            color: theme.textMuted,
          }}
        >
          <span style={{ marginRight: 8 }}>▶</span>
          <span style={{ fontWeight: 500, color: theme.text }}>{authorName}</span>
          {totalDescendants > 0 && (
            <span> and {totalDescendants} {totalDescendants === 1 ? 'other' : 'others'} ({totalDescendants + 1} {totalDescendants === 0 ? 'reply' : 'replies'})</span>
          )}
        </div>
      </div>
    )
  }

  return (
    <div style={{ marginLeft: depth > 0 ? 24 : 0 }}>
      {/* Reply context blockquote - clickable to collapse */}
      {depth > 0 && comment.parent_content && (
        <div
          onClick={() => replies.length > 0 && setExpanded(false)}
          style={{
            padding: '6px 10px',
            marginBottom: 0,
            background: theme.bgCard,
            borderLeft: `3px solid ${theme.border}`,
            borderTop: `1px solid ${theme.border}`,
            borderRight: `1px solid ${theme.border}`,
            borderTopLeftRadius: 6,
            borderTopRightRadius: 6,
            fontSize: 12,
            color: theme.textMuted,
            cursor: replies.length > 0 ? 'pointer' : 'default',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {replies.length > 0 && <span>▼</span>}
          <span>↳ replying to <strong style={{ color: theme.text }}>{parentAuthorName}</strong>: </span>
          <span style={{ fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            "{comment.parent_content}"
          </span>
        </div>
      )}

      {/* Comment body */}
      <div
        style={{
          padding: '8px 10px',
          borderLeft: depth > 0 ? `3px solid ${theme.border}` : `1px solid ${theme.border}`,
          borderRight: `1px solid ${theme.border}`,
          borderBottom: `1px solid ${theme.border}`,
          borderTop: depth > 0 && comment.parent_content ? 'none' : `1px solid ${theme.border}`,
          borderRadius: depth > 0 && comment.parent_content ? '0 0 6px 6px' : 6,
          marginBottom: 6,
          background: theme.bg,
        }}
      >
        {/* Header: user + time */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ fontWeight: 600, color: isDeleted ? theme.textMuted : theme.text, fontSize: 13 }}>
            {authorName}
          </span>
          <span style={{ color: theme.textMuted, fontSize: 12 }}>
            {formatTimeAgo(comment.created_at)}
          </span>
          {totalDescendants > 0 && (
            <span style={{ color: theme.textMuted, fontSize: 11 }}>
              • {totalDescendants} {totalDescendants === 1 ? 'reply' : 'replies'}
            </span>
          )}
        </div>

        {/* Content */}
        <div style={{ color: isDeleted ? theme.textMuted : theme.text, fontSize: 14, lineHeight: 1.5 }}>
          {isDeleted ? <em>[deleted]</em> : comment.content}
        </div>

        {/* Actions */}
        {!isDeleted && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 6 }}>
            {/* Reactions */}
            {currentUserId && (
              <ReactionBar
                targetId={comment.id}
                targetType="comment"
                reactions={reactions}
                onReactionsChange={setReactions}
                theme={theme}
                compact={true}
              />
            )}
            {/* Show reaction counts even when not logged in */}
            {!currentUserId && reactions && (reactions.counts?.['like'] > 0 || Object.keys(reactions.counts || {}).length > 1) && (
              <span style={{ fontSize: 12, color: theme.textMuted }}>
                {reactions.counts?.['like'] > 0 && `${reactions.counts['like']} like${reactions.counts['like'] !== 1 ? 's' : ''}`}
              </span>
            )}
            {canReply && (
              <button
                onClick={() => setReplyingTo(isReplyingToThis ? null : comment.id)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: theme.textMuted,
                  cursor: 'pointer',
                  fontSize: 12,
                  padding: 0,
                }}
              >
                {isReplyingToThis ? 'Cancel' : 'Reply'}
              </button>
            )}
            {canDelete && (
              <button
                onClick={handleDelete}
                disabled={deleting}
                style={{
                  background: 'none',
                  border: 'none',
                  color: theme.textMuted,
                  cursor: deleting ? 'wait' : 'pointer',
                  fontSize: 12,
                  padding: 0,
                }}
              >
                {deleting ? 'Deleting...' : 'Delete'}
              </button>
            )}
            {/* Edited indicator */}
            {comment.edited_at && (
              <EditedIndicator
                editedAt={comment.edited_at}
                onClick={() => setShowHistoryModal(true)}
                theme={theme}
              />
            )}
          </div>
        )}

        {/* Reply form */}
        {isReplyingToThis && (
          <div style={{ marginTop: 8 }}>
            <textarea
              autoFocus
              value={replyContent}
              onChange={(e) => setReplyContent((e.target as HTMLTextAreaElement).value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey && replyContent.trim()) {
                  e.preventDefault()
                  handleSubmitReply()
                }
              }}
              placeholder="Write a reply..."
              style={{
                width: '100%',
                minHeight: 40,
                padding: '6px 8px',
                borderRadius: 6,
                border: `1px solid ${theme.border}`,
                background: theme.bgCard,
                color: theme.text,
                fontSize: 13,
                resize: 'vertical',
                fontFamily: 'inherit',
              }}
            />
            <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
              <button
                onClick={handleSubmitReply}
                disabled={submittingReply || !replyContent.trim()}
                style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  border: 'none',
                  background: theme.accent,
                  color: theme.accentText,
                  fontSize: 12,
                  cursor: submittingReply ? 'wait' : 'pointer',
                  opacity: submittingReply || !replyContent.trim() ? 0.5 : 1,
                }}
              >
                {submittingReply ? 'Posting...' : 'Reply'}
              </button>
              <button
                onClick={() => { setReplyingTo(null); setReplyContent('') }}
                style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  border: `1px solid ${theme.border}`,
                  background: 'transparent',
                  color: theme.textMuted,
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Replies */}
      {replies.length > 0 && expanded && (
        <div>
          {replies.map(reply => (
            <CommentItem
              key={reply.comment.id}
              node={reply}
              thingId={thingId}
              currentUserId={currentUserId}
              thingOwnerId={thingOwnerId}
              theme={theme}
              onReply={onReply}
              onDelete={onDelete}
              replyingTo={replyingTo}
              setReplyingTo={setReplyingTo}
              replyContent={replyContent}
              setReplyContent={setReplyContent}
              submittingReply={submittingReply}
              totalComments={totalComments}
              commentable={commentable}
            />
          ))}
        </div>
      )}

      {/* Edit History Modal */}
      {showHistoryModal && (
        <EditHistoryModal
          targetId={comment.id}
          targetType="comment"
          onClose={() => setShowHistoryModal(false)}
          theme={theme}
        />
      )}
    </div>
  )
}

export function CommentsSection({
  thingId,
  thingOwnerId,
  theme,
  commentable = true,
}: {
  thingId: string
  thingOwnerId: string | null
  theme: Theme
  commentable?: boolean
}) {
  const [comments, setComments] = useState<Comment[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [newComment, setNewComment] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [replyingTo, setReplyingTo] = useState<string | null>(null)
  const [replyContent, setReplyContent] = useState('')
  const [submittingReply, setSubmittingReply] = useState(false)
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)
  const [expanded, setExpanded] = useState(true)

  useEffect(() => {
    fetchComments()
    fetchCurrentUser()
  }, [thingId])

  async function fetchCurrentUser() {
    try {
      const res = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setCurrentUserId(data.id || null)
      }
    } catch {
      // Not logged in
    }
  }

  async function fetchComments() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl(`/api/things/${thingId}/comments`), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        // API returns { success: true, data: [...] }
        setComments((data.data || data) as Comment[])
      } else {
        setError('Failed to load comments')
      }
    } catch {
      setError('Failed to load comments')
    } finally {
      setLoading(false)
    }
  }

  async function submitComment(content: string, parentId?: string) {
    const isReply = !!parentId
    if (isReply) {
      setSubmittingReply(true)
    } else {
      setSubmitting(true)
    }

    try {
      const body: Record<string, unknown> = { content }
      if (parentId) {
        body.parentId = parentId
      }

      const res = await fetch(apiUrl(`/api/things/${thingId}/comments`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include',
      })

      if (res.ok) {
        // Refresh comments
        await fetchComments()
        if (isReply) {
          setReplyingTo(null)
          setReplyContent('')
        } else {
          setNewComment('')
        }
      } else {
        const data = await res.json()
        alert(data.error || 'Failed to post comment')
      }
    } catch {
      alert('Failed to post comment')
    } finally {
      if (isReply) {
        setSubmittingReply(false)
      } else {
        setSubmitting(false)
      }
    }
  }

  async function deleteComment(commentId: string) {
    try {
      const res = await fetch(apiUrl(`/api/things/${commentId}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        await fetchComments()
      } else {
        alert('Failed to delete comment')
      }
    } catch {
      alert('Failed to delete comment')
    }
  }

  const handleReply = async (parentId: string, content: string) => {
    await submitComment(content, parentId)
  }

  const tree = buildCommentTree(comments)
  const commentCount = comments.filter(c => !c.deleted_at).length

  return (
    <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 12,
          cursor: 'pointer',
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: theme.text }}>
          Replies {commentCount > 0 && `(${commentCount})`}
        </h3>
        <span style={{ color: theme.textMuted, fontSize: 12 }}>
          {expanded ? '▼' : '▶'}
        </span>
      </div>

      {expanded && (
        <>
          {/* New reply form - only if commentable */}
          {commentable && currentUserId && (
            <div style={{ marginBottom: 12 }}>
              <textarea
                value={newComment}
                onChange={(e) => setNewComment((e.target as HTMLTextAreaElement).value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey && newComment.trim()) {
                    e.preventDefault()
                    submitComment(newComment)
                  }
                }}
                placeholder="Write a reply..."
                style={{
                  width: '100%',
                  minHeight: 44,
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: `1px solid ${theme.border}`,
                  background: theme.bgCard,
                  color: theme.text,
                  fontSize: 13,
                  resize: 'vertical',
                  fontFamily: 'inherit',
                }}
              />
              <button
                onClick={() => submitComment(newComment)}
                disabled={submitting || !newComment.trim()}
                style={{
                  marginTop: 6,
                  padding: '6px 12px',
                  borderRadius: 6,
                  border: 'none',
                  background: theme.accent,
                  color: theme.accentText,
                  fontSize: 12,
                  cursor: submitting ? 'wait' : 'pointer',
                  opacity: submitting || !newComment.trim() ? 0.5 : 1,
                }}
              >
                {submitting ? 'Posting...' : 'Reply'}
              </button>
            </div>
          )}

          {commentable && !currentUserId && (
            <p style={{ color: theme.textMuted, fontSize: 13, marginBottom: 16 }}>
              <a href={routeHref('/login')} style={{ color: theme.accent }}>Log in</a> to reply.
            </p>
          )}

          {/* Comments list */}
          {loading ? (
            <p style={{ color: theme.textMuted, fontSize: 13 }}>Loading replies...</p>
          ) : error ? (
            <p style={{ color: theme.error, fontSize: 13 }}>{error}</p>
          ) : tree.length === 0 ? (
            commentable ? (
              <p style={{ color: theme.textMuted, fontSize: 13 }}>No replies yet. Be the first!</p>
            ) : null
          ) : (
            <div>
              {tree.map(node => (
                <CommentItem
                  key={node.comment.id}
                  node={node}
                  thingId={thingId}
                  currentUserId={currentUserId}
                  thingOwnerId={thingOwnerId}
                  theme={theme}
                  onReply={handleReply}
                  onDelete={deleteComment}
                  replyingTo={replyingTo}
                  setReplyingTo={setReplyingTo}
                  replyContent={replyContent}
                  setReplyContent={setReplyContent}
                  submittingReply={submittingReply}
                  totalComments={comments.length}
                  commentable={commentable}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// Bookmarks View
