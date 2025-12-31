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

  const tabStyle = (isActive: boolean) => ({
    padding: '8px 16px',
    background: isActive ? theme.accent : 'transparent',
    color: isActive ? theme.accentText : theme.textMuted,
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    fontSize: 14,
    fontWeight: isActive ? 600 : 400,
  })

  return (
    <div>
      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: theme.bgMuted, padding: 4, borderRadius: 8, width: 'fit-content', flexWrap: 'wrap' }}>
        <button onClick={() => setActiveTab('kinds')} style={tabStyle(activeTab === 'kinds')}>
          Kinds
        </button>
        <button onClick={() => setActiveTab('friends')} style={tabStyle(activeTab === 'friends')}>
          Friends
        </button>
        <button onClick={() => setActiveTab('integrations')} style={tabStyle(activeTab === 'integrations')}>
          Integrations
        </button>
        <button onClick={() => setActiveTab('data')} style={tabStyle(activeTab === 'data')}>
          Data
        </button>
        <button onClick={() => setActiveTab('keys')} style={tabStyle(activeTab === 'keys')}>
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
