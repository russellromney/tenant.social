import { useState } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind } from '../types'
import { KindsPanel, DataExportPanel, APIKeysPanel } from './SettingsPanels'
import { IntegrationsPanel } from './IntegrationsPanel'
import { FriendsView } from './FriendsView'

// Settings Page with Tabs
export function SettingsPage({
  theme,
  kinds,
  onImportComplete,
  onCreateKind,
  onDeleteKind,
  setEditingKind,
  usedEmojis,
  isMobile,
  defaultKindId,
  onSetDefaultKind,
  initialTab = 'kinds',
}: {
  theme: Theme
  kinds: Kind[]
  onImportComplete: () => void
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
  isMobile: boolean
  defaultKindId: string | null
  onSetDefaultKind: (id: string | null) => void
  initialTab?: 'kinds' | 'data' | 'keys' | 'friends' | 'integrations'
}) {
  const [activeTab, setActiveTab] = useState<'kinds' | 'data' | 'keys' | 'friends' | 'integrations'>(initialTab)

  return (
    <div>
      {/* Tab Navigation */}
      <div className="flex gap-1 mb-6 bg-muted p-1 rounded-lg w-fit flex-wrap">
        <button
          onClick={() => setActiveTab('kinds')}
          className="px-4 py-2 rounded-md border-0 cursor-pointer text-sm"
          style={{
            background: activeTab === 'kinds' ? theme.accent : 'transparent',
            color: activeTab === 'kinds' ? theme.accentText : theme.textMuted,
            fontWeight: activeTab === 'kinds' ? 600 : 400,
          }}
        >
          Kinds
        </button>
        <button
          onClick={() => setActiveTab('friends')}
          className="px-4 py-2 rounded-md border-0 cursor-pointer text-sm"
          style={{
            background: activeTab === 'friends' ? theme.accent : 'transparent',
            color: activeTab === 'friends' ? theme.accentText : theme.textMuted,
            fontWeight: activeTab === 'friends' ? 600 : 400,
          }}
        >
          Friends
        </button>
        <button
          onClick={() => setActiveTab('integrations')}
          className="px-4 py-2 rounded-md border-0 cursor-pointer text-sm"
          style={{
            background: activeTab === 'integrations' ? theme.accent : 'transparent',
            color: activeTab === 'integrations' ? theme.accentText : theme.textMuted,
            fontWeight: activeTab === 'integrations' ? 600 : 400,
          }}
        >
          Integrations
        </button>
        <button
          onClick={() => setActiveTab('data')}
          className="px-4 py-2 rounded-md border-0 cursor-pointer text-sm"
          style={{
            background: activeTab === 'data' ? theme.accent : 'transparent',
            color: activeTab === 'data' ? theme.accentText : theme.textMuted,
            fontWeight: activeTab === 'data' ? 600 : 400,
          }}
        >
          Data
        </button>
        <button
          onClick={() => setActiveTab('keys')}
          className="px-4 py-2 rounded-md border-0 cursor-pointer text-sm"
          style={{
            background: activeTab === 'keys' ? theme.accent : 'transparent',
            color: activeTab === 'keys' ? theme.accentText : theme.textMuted,
            fontWeight: activeTab === 'keys' ? 600 : 400,
          }}
        >
          API Keys
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'kinds' ? (
        <KindsPanel
          kinds={kinds}
          onCreateKind={onCreateKind}
          onDeleteKind={onDeleteKind}
          setEditingKind={setEditingKind}
          usedEmojis={usedEmojis}
          theme={theme}
          defaultKindId={defaultKindId}
          onSetDefaultKind={onSetDefaultKind}
        />
      ) : activeTab === 'friends' ? (
        <FriendsView theme={theme} isMobile={isMobile} />
      ) : activeTab === 'integrations' ? (
        <IntegrationsPanel theme={theme} kinds={kinds} />
      ) : activeTab === 'data' ? (
        <DataExportPanel theme={theme} onImportComplete={onImportComplete} />
      ) : (
        <APIKeysPanel theme={theme} />
      )}
    </div>
  )
}
