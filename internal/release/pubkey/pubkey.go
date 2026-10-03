// Package pubkey holds the public half of the release signing key. The Hub
// puts it into the install script; the agent verifies upgrades with it.
package pubkey

import _ "embed"

//go:embed pubkey.pem
var PEM []byte
