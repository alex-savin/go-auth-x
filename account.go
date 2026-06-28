package authx

import (
	"net/http"
	"strconv"
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
	c.JSON(http.StatusOK, H{
		"email":           au.Email,
		"name":            au.Name,
		"emailVerified":   au.EmailVerified,
		"hasPassword":     perr == nil,
		"passkeysEnabled": a.wauthn != nil,
		"passkeys":        views,
	})
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
	if msg := passwordStrengthError(body.New, au.Email); msg != "" {
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
	pks, _ := a.creds.Passkeys(au.ID)
	_, _, perr := a.creds.PasswordHash(au.ID)
	if perr != nil && len(pks) <= 1 {
		c.JSON(http.StatusConflict, H{"error": "add a password or another passkey before removing your last one"})
		return
	}
	if err := a.creds.RemovePasskey(au.ID, uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, H{"error": "could not remove passkey"})
		return
	}
	a.creds.RecordAudit(au.ID, au.Email, c.ClientIP(), "passkey", "passkey_removed", true, "")
	c.JSON(http.StatusOK, H{"ok": true})
}
