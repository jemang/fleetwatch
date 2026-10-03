// Command fleetwatch-agent collects host metrics and pushes them to the Hub.
// It has no inbound listener and executes no commands. The service is
// controlled over D-Bus, never by starting another program.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fleetwatch/internal/agent"
	"fleetwatch/internal/agent/client"
	"fleetwatch/internal/agent/collect"
	"fleetwatch/internal/agent/config"
	"fleetwatch/internal/agent/pve"
	"fleetwatch/internal/agent/systemd"
	"fleetwatch/internal/agent/upgrade"
	"fleetwatch/internal/protocol"
	"fleetwatch/internal/release/pubkey"
)

const (
	usage    = "usage: fleetwatch-agent <enroll|run|status|upgrade|uninstall|version>"
	unitName = "fleetwatch-agent.service"
	svcUser  = "fleetwatch"
	// onlineWithin is the Hub's own limit: a host is offline 45 seconds after
	// its last report.
	onlineWithin = 45 * time.Second
)

type serviceManager interface {
	Stop(unit string) error
	Disable(unit string) error
	Reload() error
	TryRestart(unit string) error
	Close()
}

// Replaced in tests.
var (
	connectSystemd = func() (serviceManager, error) {
		m, err := systemd.Connect()
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	isRoot     = func() bool { return os.Geteuid() == 0 }
	executable = func() (string, error) {
		p, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(p)
	}
	unitPath   = "/etc/systemd/system/" + unitName
	releaseKey = pubkey.PEM
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "enroll":
		return enroll(args[1:], stdout, stderr)
	case "run":
		return runAgent(args[1:], stderr)
	case "status":
		return status(args[1:], stdout, stderr)
	case "upgrade":
		return upgradeAgent(args[1:], stdout, stderr)
	case "uninstall":
		return uninstall(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, agent.Version)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n%s\n", args[0], usage)
	return 2
}

func orEnv(flagValue, name string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(name)
}

func enroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hub := fs.String("hub", "", "Hub URL")
	token := fs.String("token", "", "single-use enrollment token")
	cfgPath := fs.String("config", config.DefaultPath, "config file to write")
	insecure := fs.Bool("allow-insecure-http", false, "permit a plain http:// Hub URL")
	root := fs.String("proc-root", "", "filesystem root to read /proc from")
	services := fs.String("services", "", "comma-separated systemd units to watch, for example nginx,docker")
	pveID := fs.String("pve-token-id", "", "Proxmox API token ID, for example fleetwatch@pve!agent")
	pveSecret := fs.String("pve-token-secret", "", "Proxmox API token secret")
	pveCA := fs.String("pve-ca-file", "", "certificate that signs the Proxmox API, if not /etc/pve/pve-root-ca.pem")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *token == "" {
		fmt.Fprintln(stderr, "enroll: --token is required")
		return 2
	}
	if err := config.CheckHubURL(*hub, *insecure); err != nil {
		fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	hostname := collect.ReadHostInfo(*root).Hostname
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := client.New(*hub, "").Enroll(ctx, protocol.EnrollRequest{
		Token: *token, Hostname: hostname, AgentVersion: agent.Version, ProtocolVersion: protocol.Version,
	})
	if errors.Is(err, client.ErrUnauthorized) {
		fmt.Fprintln(stderr, "enroll: the Hub rejected the token (already used, expired or revoked); create a new one with Add Server")
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	cfg := config.Config{
		HubURL: strings.TrimRight(*hub, "/"), AgentID: resp.AgentID, AgentToken: resp.AgentToken,
		Interval: config.DefaultInterval, AllowInsecureHTTP: *insecure,
	}
	// A server that enrolls again (new credential) keeps its other settings.
	if old, err := config.Load(*cfgPath, func(string) string { return "" }); err == nil {
		cfg.Interval, cfg.Services, cfg.Proxmox = old.Interval, old.Services, old.Proxmox
	}
	// The installer passes options in the environment, which keeps the
	// Proxmox secret out of the process list.
	if v := orEnv(*services, "FLEETWATCH_SERVICES"); v != "" {
		cfg.Services = config.UnitNames(strings.Split(v, ","))
	}
	if v := orEnv(*pveID, "FLEETWATCH_PVE_TOKEN_ID"); v != "" {
		cfg.Proxmox.TokenID = v
	}
	if v := orEnv(*pveSecret, "FLEETWATCH_PVE_TOKEN_SECRET"); v != "" {
		cfg.Proxmox.TokenSecret = v
	}
	if *pveCA != "" {
		cfg.Proxmox.CAFile = *pveCA
	}
	if err := config.Save(*cfgPath, cfg); err != nil {
		fmt.Fprintf(stderr, "enroll: registered, but the config could not be written: %v\n", err)
		return 1
	}
	// A running service still holds the old credential.
	if mgr, err := connectSystemd(); err == nil {
		mgr.TryRestart(unitName)
		mgr.Close()
	}
	fmt.Fprintf(stdout, "Server registered: %s (agent %s)\nConfig written to %s\n", hostname, resp.AgentID, *cfgPath)
	return 0
}

func ago(d time.Duration) string {
	n, word := int(d.Seconds()), "second"
	switch {
	case d >= 24*time.Hour:
		n, word = int(d.Hours())/24, "day"
	case d >= time.Hour:
		n, word = int(d.Hours()), "hour"
	case d >= time.Minute:
		n, word = int(d.Minutes()), "minute"
	}
	if n != 1 {
		word += "s"
	}
	return fmt.Sprintf("%d %s ago", n, word)
}

// status asks the Hub how it knows this agent. It returns 0 only when the
// Hub received a report recently.
func status(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "status: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	self, err := client.New(cfg.HubURL, cfg.AgentToken).Self(ctx)
	switch {
	case errors.Is(err, client.ErrUnauthorized):
		fmt.Fprintf(stderr, "Status: the Hub at %s does not accept this agent (its credential was replaced, or the agent is disabled)\n", cfg.HubURL)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "Status: cannot reach the Hub at %s: %v\n", cfg.HubURL, err)
		return 1
	}
	fmt.Fprintf(stdout, "Server: %s\nHub:    %s\n", self.Name, cfg.HubURL)
	if self.LastSeen == 0 {
		fmt.Fprintln(stdout, "Status: Waiting for the first report")
		return 1
	}
	age := time.Duration(self.Now-self.LastSeen) * time.Second
	if age > onlineWithin {
		fmt.Fprintf(stdout, "Status: Offline (last report %s)\n", ago(age))
		return 1
	}
	fmt.Fprintf(stdout, "Status: Online (last report %s)\n", ago(age))
	return 0
}

// upgradeAgent installs the release the Hub offers, if the key compiled into
// this program signed it.
func upgradeAgent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	downgrade := fs.Bool("allow-downgrade", false, "install the offered version even if it is older")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !isRoot() {
		fmt.Fprintln(stderr, "upgrade: run this as root, for example with sudo")
		return 1
	}
	cfg, err := config.Load(*cfgPath, os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "upgrade: %v\n", err)
		return 1
	}
	exe, err := executable()
	if err != nil {
		fmt.Fprintf(stderr, "upgrade: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := upgrade.Run(ctx, upgrade.Options{
		Fetch: client.New(cfg.HubURL, "").Download, PublicKey: releaseKey, Arch: runtime.GOARCH,
		Current: agent.Version, Exe: exe, AllowDowngrade: *downgrade,
	})
	if err != nil {
		fmt.Fprintf(stderr, "upgrade: %v\nNothing was changed.\n", err)
		return 1
	}
	if !res.Changed {
		fmt.Fprintf(stdout, "Already up to date (version %s).\n", res.From)
		return 0
	}
	fmt.Fprintf(stdout, "Upgraded from %s to %s.\n", res.From, res.To)
	mgr, err := connectSystemd()
	if err == nil {
		err = mgr.TryRestart(unitName)
		mgr.Close()
	}
	if err != nil {
		fmt.Fprintln(stdout, "The new version runs after the service restarts: systemctl restart fleetwatch-agent")
		return 0
	}
	fmt.Fprintln(stdout, "Service restarted.")
	return 0
}

// uninstall removes the service, the config with its credential, and this
// program.
func uninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !isRoot() {
		fmt.Fprintln(stderr, "uninstall: run this as root, for example with sudo")
		return 1
	}
	failed := false
	step := func(what string, err error) {
		if err == nil || errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stdout, "\u2713 %s\n", what)
			return
		}
		failed = true
		fmt.Fprintf(stderr, "\u2717 %s: %v\n", what, err)
	}
	mgr, err := connectSystemd()
	if err != nil {
		fmt.Fprintf(stderr, "systemd is not reachable (%v); a running agent is not stopped\n", err)
	} else {
		// Neither call fails the uninstall: the unit may be gone already.
		mgr.Stop(unitName)
		mgr.Disable(unitName)
		fmt.Fprintln(stdout, "\u2713 Service stopped and disabled")
	}
	step("Service definition removed", os.Remove(unitPath))
	if mgr != nil {
		mgr.Reload()
		mgr.Close()
	}
	// Only the files the installer made are removed, then the directory if it
	// is empty. A wrong --config can therefore not delete anything else.
	dir := filepath.Dir(*cfgPath)
	step("Config and credential removed", errors.Join(os.Remove(*cfgPath), os.Remove(filepath.Join(dir, "pve-root-ca.pem"))))
	os.Remove(dir)
	exe, err := executable()
	if err == nil {
		err = os.Remove(exe)
	}
	step("Program removed", err)
	if _, err := user.Lookup(svcUser); err == nil {
		fmt.Fprintf(stdout, "\nThe system user %q was left in place, because removing it needs another program. Remove it with: userdel %s\n", svcUser, svcUser)
	}
	if failed {
		return 1
	}
	fmt.Fprintln(stdout, "FleetWatch agent removed. The server stays in the dashboard as offline until its agent is disabled there.")
	return 0
}

func runAgent(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	root := fs.String("proc-root", "", "filesystem root to read /proc and /sys from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, os.Getenv)
	if err != nil {
		fmt.Fprintf(stderr, "run: %v\n", err)
		return 1
	}
	logger := log.New(stderr, "fleetwatch-agent: ", log.LstdFlags)
	if strings.HasPrefix(cfg.HubURL, "http://") {
		logger.Printf("WARNING: reporting over plain HTTP to %s; the agent token is sent unencrypted", cfg.HubURL)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Proxmox is read in the background so a slow API never delays a report.
	proxmox := &pve.Collector{Root: *root, Now: time.Now}
	if p := cfg.Proxmox; p.TokenID != "" && p.TokenSecret != "" {
		pc := pve.Config{APIURL: p.APIURL, TokenID: p.TokenID, TokenSecret: p.TokenSecret, CAFile: p.CAFile}
		if pc.APIURL == "" {
			pc.APIURL = pve.DefaultAPIURL
		}
		if pc.CAFile == "" {
			pc.CAFile = pve.DefaultCAFile
		}
		if proxmox.Client, err = pve.NewClient(pc); err != nil {
			logger.Printf("Proxmox API not usable, guests will not be reported: %v", err)
		}
	}
	if proxmox.Detected() {
		go proxmox.Run(ctx, collect.SlowEvery)
	}

	r := &agent.Runner{
		Sampler: &collect.Sampler{Root: *root, Statfs: collect.Statfs, Addrs: collect.SystemAddrs, Now: time.Now, Timeout: 5 * time.Second,
			Services: cfg.Services, ListServices: new(systemd.Lister).List, Proxmox: proxmox.Latest},
		Sender:   client.New(cfg.HubURL, cfg.AgentToken),
		Interval: cfg.Interval,
		Now:      time.Now,
		Sleep:    agent.Sleep,
		Jitter:   agent.DefaultJitter,
		Log:      logger.Printf,
	}
	logger.Printf("version %s reporting to %s every %s", agent.Version, cfg.HubURL, cfg.Interval)
	if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("stopped: %v", err)
		return 1
	}
	return 0
}
