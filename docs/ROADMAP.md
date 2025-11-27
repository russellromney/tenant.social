# Tenant Roadmap

## Completed
- [x] Multi-user authentication (register, login, sessions)
- [x] User-scoped data (Things, Kinds, Tags, Views)
- [x] Server admin role (first user is admin)
- [x] Admin can lock/unlock users
- [x] Admin can delete users

## In Progress
- [ ] Fix tests for multi-user API
- [ ] Deploy to Fly.io

## Next Up

### Recovery Phrase System
Users need a recovery phrase for account recovery and data export:
1. **On registration**: Generate a 12-24 word mnemonic phrase (BIP39 style)
2. **Store hash**: Store bcrypt hash of the phrase in `recovery_hash` field
3. **User must save**: Show phrase ONCE, require user to confirm they saved it
4. **Password recovery**: If user forgets password but has recovery phrase:
   - Verify recovery phrase
   - Allow password reset
5. **Locked account data export**: If admin locks a user:
   - User can still use recovery phrase to export their data
   - Data export is read-only, no modifications allowed
6. **Admin recovery**: Admin also gets a recovery phrase for password recovery

### Encrypted Data Backup
For when servers shut down or users want portable backups:
1. **Encryption key derivation**: Derive encryption key from recovery phrase
2. **Export encrypted backup**:
   - Export all user data (Things, Kinds, Tags, Views, Photos)
   - Encrypt with key derived from recovery phrase
   - Produce single downloadable file
3. **Import to new server**:
   - User creates account on new server
   - Uploads encrypted backup
   - Enters recovery phrase to decrypt
   - Data is imported to new account

### Future Features
- [ ] Public profiles (optional, user-controlled)
- [ ] Sharing Things between users
- [ ] API keys for external integrations
- [ ] Webhooks for data changes
- [ ] Full-text search with FTS5
- [ ] Data encryption at rest (optional, per-user)
