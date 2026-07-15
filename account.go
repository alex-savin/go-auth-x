package authx

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// passkeyView is the JSON-safe projection of a passkey (no credential bytes).
type passkeyView struct {
	ID         uint      `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}

// AccountInfo (GET /auth/api/account) returns the signed-in user's identity + sign-in methods.
func (a *Authenticator) AccountInfo(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	pks, _ := a.creds.Passkeys(au.ID)
	views := make([]passkeyView, 0, len(pks))
	for _, p := range pks {
		views = append(views, passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
	}
	_, _, perr := a.creds.PasswordHash(au.ID)
	oauthIDs, _ := a.creds.OAuthIdentities(au.ID)
	c.JSON(http.StatusOK, H{
		"email":           au.Email,
		"name":            au.Name,
		"emailVerified":   au.EmailVerified,
		"hasPassword":     perr == nil,
		"passkeysEnabled": a.wauthn != nil,
		"passkeys":        views,
		"oauth":           oauthIDs,          // linked social/OIDC providers, for unlink UI
		"sessionsEnabled": a.sessions != nil, // whether the "your devices" endpoints are available
	})
}

// signInMethods counts a user's independent sign-in methods: a password, each passkey, and each linked
// OAuth provider. Used to refuse removing the LAST one (which would lock the user out).
func (a *Authenticator) signInMethods(userID uint) (total int) {
	if _, _, perr := a.creds.PasswordHash(userID); perr == nil {
		total++
	}
	pks, _ := a.creds.Passkeys(userID)
	total += len(pks)
	ids, _ := a.creds.OAuthIdentities(userID)
	total += len(ids)
	return total
}

// AccountSetPassword (POST /auth/api/account/password) sets or changes the signed-in user's
// password. If one already exists, the current password is required.
func (a *Authenticator) AccountSetPassword(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	var body struct{ Current, New string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	if hash, _, perr := a.creds.PasswordHash(au.ID); perr == nil {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Current)) != nil {
			c.JSON(http.StatusForbidden, H{"error": "current password is incorrect"})
			return
		}
	}
	if msg := a.passwordPolicyError(c.Request.Context(), body.New, au.Email); msg != "" {
		c.JSON(http.StatusBadRequest, H{"error": msg})
		return
	}
	hash, herr := hashPassword(body.New)
	if herr != nil || a.creds.SetPasswordHash(au.ID, hash, "bcrypt") != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not update password"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "password", "password_changed", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// PasskeyRemove (DELETE /auth/api/passkeys/:id) deletes one of the user's passkeys, refusing
// to remove their last remaining sign-in method.
func (a *Authenticator) PasskeyRemove(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid id"})
		return
	}
	// Refuse to remove the last sign-in method across ALL kinds (password + passkeys + OAuth), not just
	// passkeys — otherwise an OAuth-only user could delete their only passkey and be locked out. The
	// check-and-remove is serialized (credMu) so two concurrent removals can't both pass and race to zero.
	a.credMu.Lock()
	last := a.signInMethods(au.ID) <= 1
	if !last {
		err = a.creds.RemovePasskey(au.ID, uint(id))
	}
	a.credMu.Unlock()
	if last {
		c.JSON(http.StatusConflict, H{"error": "add a password or another sign-in method before removing your last one"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not remove passkey"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "passkey", "passkey_removed", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}

// PasskeyRename (POST /auth/api/passkeys/{id}) relabels one of the user's passkeys.
func (a *Authenticator) PasskeyRename(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid id"})
		return
	}
	var body struct{ Name string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, H{"error": "invalid request"})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 64 {
		c.JSON(http.StatusBadRequest, H{"error": "name must be 1–64 characters"})
		return
	}
	if err := a.creds.RenamePasskey(au.ID, uint(id), name); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not rename passkey"})
		return
	}
	c.JSON(http.StatusOK, H{"ok": true})
}

// OAuthUnlink (DELETE /auth/api/identities/{provider}) removes a linked social/OIDC identity, refusing
// to strip the user's last sign-in method. Not step-up gated (parity with PasskeyRemove, and so an
// OAuth-only user with two providers can still unlink one).
func (a *Authenticator) OAuthUnlink(c *reqCtx) {
	au, err := a.currentAuthUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, H{"error": "unauthenticated"})
		return
	}
	provider := c.Param("provider")
	ids, _ := a.creds.OAuthIdentities(au.ID)
	linked := false
	for _, p := range ids {
		if p == provider {
			linked = true
			break
		}
	}
	if !linked {
		c.JSON(http.StatusNotFound, H{"error": "no such linked account"})
		return
	}
	// Serialized check-and-remove (see PasskeyRemove) so concurrent unlinks can't strip the last method.
	a.credMu.Lock()
	last := a.signInMethods(au.ID) <= 1
	if !last {
		err = a.creds.UnlinkOAuth(au.ID, provider)
	}
	a.credMu.Unlock()
	if last {
		c.JSON(http.StatusConflict, H{"error": "add a password or another sign-in method before unlinking your last one"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not unlink account"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "oauth", "unlinked", true, provider)
	c.JSON(http.StatusOK, H{"ok": true})
}
