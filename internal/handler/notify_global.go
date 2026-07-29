package handler

import "github.com/violetaini/relaydock/internal/notify"

var globalNotifier *notify.Notifier

func InitNotifier(cfg notify.Config) {
	globalNotifier = notify.New(cfg)
}

func GetNotifier() *notify.Notifier {
	return globalNotifier
}
