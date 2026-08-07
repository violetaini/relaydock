// Package config defines the embedded TGBot runtime configuration. Persistence
// is owned by the master system_settings table; there is no standalone YAML,
// master address or master API-token configuration after the merge.
package config

type Config struct {
	Enabled bool
	// PublicBaseURL is derived from the master's existing public URL setting and
	// is used only when rendering subscription links in Telegram messages.
	PublicBaseURL      string
	TGBotToken         string
	AdminTGIDs         []int64
	HTTPTimeoutSeconds int
	WebAppURL          string
	WebAppDevPreview   bool
}

func (c Config) IsAdmin(tgID int64) bool {
	for _, id := range c.AdminTGIDs {
		if id == tgID {
			return true
		}
	}
	return false
}
