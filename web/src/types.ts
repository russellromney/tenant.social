// Core data types for Tenant

export interface Attribute {
  name: string
  type: string
  required: boolean
  options: string // comma-separated for select type
}

export interface Kind {
  id: string
  name: string
  icon: string  // Emoji
  template: 'default' | 'compact' | 'card' | 'checklist' | 'link' | 'photo'
  attributes: Attribute[]
  commentable: boolean
  show_existing_comments: boolean
  reactable: boolean
  created_at: string
  updated_at: string
  isDefault?: boolean // for UI-only default kinds
}

// Available templates for display
export const TEMPLATES = [
  { id: 'default', name: 'Default', description: 'Standard card with content and metadata' },
  { id: 'compact', name: 'Compact', description: 'Minimal one-line display' },
  { id: 'card', name: 'Card', description: 'Rich card with prominent content' },
  { id: 'checklist', name: 'Checklist', description: 'Task-style with checkbox' },
  { id: 'link', name: 'Link', description: 'URL-focused with clickable link' },
  { id: 'photo', name: 'Photo', description: 'Image/video gallery display' },
] as const

export interface Photo {
  id: string
  thing_id: string
  caption: string
  order_index: number
  content_type: string
  filename: string
  size: number
  created_at: string
}

export interface Thing {
  id: string
  type: string
  content: string
  metadata: Record<string, unknown>
  visibility: 'private' | 'friends' | 'public'
  created_at: string
  updated_at: string
  edited_at?: string | null
  photos?: Photo[]
  deleted_at?: string | null
  user_id?: string
  comment_count?: number
  top_replies?: Thing[]
}

// Reaction system types
export interface ReactionSummary {
  counts: Record<string, number>
  user_reactions: string[]
}

export interface EditHistoryEntry {
  id: string
  target_id: string
  target_type: 'thing' | 'comment'
  content: string
  edited_at: string
}

// Author info for comments
export interface CommentAuthor {
  user_id: string
  username: string
  display_name: string
}

// Comment with author info (from API)
export interface Comment extends Thing {
  metadata: {
    root_id: string
    parent_id: string
    depth: number
    [key: string]: unknown
  }
  // Enriched fields from API
  author?: CommentAuthor
  parent_content?: string
  parent_author?: CommentAuthor
}

export interface Follow {
  id: string
  follower_id: string
  following_id: string
  remote_endpoint: string
  access_token: string | null
  created_at: string
  last_confirmed_at?: string | null
}

export interface RemoteProfile {
  id: string
  username: string
  display_name: string
  bio: string
  avatar_url: string
}

export interface FriendFeedItem extends Thing {
  owner_username?: string
  owner_endpoint?: string
}

// Default kinds - will be created in DB on first load
export const DEFAULT_KINDS: Omit<Kind, 'created_at' | 'updated_at'>[] = [
  { id: 'default-post', name: 'post', icon: '💬', template: 'default', attributes: [], commentable: true, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-note', name: 'note', icon: '📝', template: 'default', attributes: [], commentable: false, show_existing_comments: false, reactable: false, isDefault: true },
  { id: 'default-link', name: 'link', icon: '🔗', template: 'link', attributes: [{ name: 'url', type: 'url', required: true, options: '' }], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-task', name: 'task', icon: '✅', template: 'checklist', attributes: [{ name: 'done', type: 'checkbox', required: false, options: '' }], commentable: false, show_existing_comments: false, reactable: false, isDefault: true },
  { id: 'default-photo', name: 'photo', icon: '📷', template: 'photo', attributes: [], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-gallery', name: 'gallery', icon: '🖼️', template: 'photo', attributes: [], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
]

// Auth status from the server
export interface AuthStatus {
  hasOwner: boolean
  registrationEnabled: boolean
  sandboxMode: boolean
  authDisabled: boolean
}

// API Key types
export interface ApiKey {
  id: string
  name: string
  scopes: string[]
  created_at: string
  last_used_at?: string | null
}

// User types
export interface User {
  id: string
  username: string
  display_name: string
  bio?: string
  avatar_url?: string
  is_admin?: boolean
}
