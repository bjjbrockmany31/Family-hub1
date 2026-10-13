# Homebase Family App — shareable invitation links

This version adds **real cross-phone family membership** with personal accounts and shared family data.

### Run locally

1. Install Node.js 20 or newer.
2. Open a terminal in this folder.
3. Run `npm start` (no install needed; the backend uses built-in Node.js modules).
4. On your own computer, open `http://localhost:3000`.
5. Create your first account — this creates your family.
6. Tap **Invite someone to the family** on the home screen, or go to **Family Profiles → Send invite link**.

An invite looks like `https://your-homebase-site.com/?join=unique-private-code`. A family member opens the link on their phone, chooses their own name, username and password, and joins the same family. Existing members can log in normally.

### Put it online (required to share across phones)

Deploy this **entire folder** on any Node.js host with HTTPS, set start command to `npm start`, and make sure `PORT` is set by the host. Use **persistent storage** for the `data/` folder (or provide a persisted directory with the `DATA_DIR` environment variable); otherwise users and stats disappear when the server restarts or the host redeploys. Do **not** use GitHub Pages alone — it runs static HTML, not the login and sync backend. Different platforms charge differently for persistent disks.

Once deployed, open the live website link from your phone, sign up, and press **Share invite link**. The app uses your *actual website address* automatically. There is no hard-coded demo domain.

### Privacy and limitations

- Passwords are processed on the server with salted scrypt hashes (never stored in plain text).
- Private invitation links contain a random unguessable token; anyone with the link can join, so share it only with family. Rotate the token using the `/api/invites/rotate` endpoint if compromised (requires a signed-in member); a UI can be added for this.
- Shared lists, calendars, XP and profile stats sync on saved changes and when the app regains focus, generally within 12 seconds.
- If two users edit at exactly the same time, the app shows a change conflict to avoid silently overwriting family records; refresh before editing more.
- The local offline HTML still works as a demo on one phone, but invitation links only work when served by `server.js` from a public HTTPS host.
- This is a family-sized MVP, not a managed enterprise identity service. For public-scale deployment, add email-based password reset, encrypted backups, stronger auditing and database-backed transactional writes.
- Never commit or publicly upload the `data/` folder.
