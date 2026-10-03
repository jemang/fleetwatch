// Package upgrade replaces the installed agent file with the release a Hub
// offers, after verifying it with the release key.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"fleetwatch/internal/release"
)

type Options struct {
	// Fetch downloads one release file by name.
	Fetch          func(ctx context.Context, name string) ([]byte, error)
	PublicKey      []byte // PEM; the release must be signed by this key
	Arch           string
	Current        string // installed version
	Exe            string // installed file
	AllowDowngrade bool
}

type Result struct {
	From, To string
	Changed  bool
}

// older reports whether version a is lower than b. Both are three numbers.
func older(a, b string) (bool, error) {
	parse := func(v string) ([3]int, error) {
		var out [3]int
		parts := strings.Split(v, ".")
		if len(parts) != 3 {
			return out, fmt.Errorf("upgrade: version %q is not three numbers", v)
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return out, fmt.Errorf("upgrade: version %q is not three numbers", v)
			}
			out[i] = n
		}
		return out, nil
	}
	x, err := parse(a)
	if err != nil {
		return false, err
	}
	y, err := parse(b)
	if err != nil {
		return false, err
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i], nil
		}
	}
	return false, nil
}

// Run verifies the offered release and installs its file for this processor
// type. Nothing is written unless every check passes.
func Run(ctx context.Context, o Options) (Result, error) {
	res := Result{From: o.Current}
	sums, err := o.Fetch(ctx, release.SumsFile)
	if err != nil {
		return res, err
	}
	sig, err := o.Fetch(ctx, release.SigFile)
	if err != nil {
		return res, err
	}
	if err := release.Verify(o.PublicKey, sums, sig); err != nil {
		return res, err
	}
	ver, err := o.Fetch(ctx, release.VersionFile)
	if err != nil {
		return res, err
	}
	if err := release.Check(sums, release.VersionFile, ver); err != nil {
		return res, err
	}
	res.To = strings.TrimSpace(string(ver))
	if !o.AllowDowngrade {
		down, err := older(res.To, o.Current)
		if err != nil {
			return res, err
		}
		if down {
			return res, fmt.Errorf("upgrade: the Hub offers version %s, which is older than the installed %s; use --allow-downgrade to install it", res.To, o.Current)
		}
	}
	name := release.AgentFile(o.Arch)
	want, ok := release.SumFor(sums, name)
	if !ok {
		return res, fmt.Errorf("upgrade: the release has no file for processor type %s", o.Arch)
	}
	if cur, err := os.ReadFile(o.Exe); err == nil {
		if sum := sha256.Sum256(cur); hex.EncodeToString(sum[:]) == want {
			return res, nil
		}
	}
	bin, err := o.Fetch(ctx, name)
	if err != nil {
		return res, err
	}
	if err := release.Check(sums, name, bin); err != nil {
		return res, err
	}
	// Written beside the target, then renamed: the installed file is either
	// the old one or the new one, never half of each.
	tmp := o.Exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return res, err
	}
	if err := os.Chmod(tmp, 0o755); err == nil {
		err = os.Rename(tmp, o.Exe)
	}
	if err != nil {
		os.Remove(tmp)
		return res, err
	}
	res.Changed = true
	return res, nil
}
