// Command fakepve is a stand-in for the Proxmox VE API, for tests on machines
// without Proxmox. It serves fixed replies over TLS with a certificate it
// creates at start, and writes that certificate where the agent expects the
// cluster CA. It is not part of the product.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	caPath := flag.String("ca", "/etc/pve/pve-root-ca.pem", "where to write the certificate the agent must trust")
	listen := flag.String("listen", "127.0.0.1:8006", "listen address")
	token := flag.String("token", "fleetwatch@pve!agent=fake-secret", "accepted token, as <id>=<secret>")
	flag.Parse()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "fakepve"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*caPath), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}

	node, _ := os.Hostname()
	started := time.Now()
	replies := map[string]func() string{
		"/api2/json/version": func() string { return `{"data":{"version":"8.2.4","release":"8.2","repoid":"fakepve"}}` },
		"/api2/json/cluster/status": func() string {
			return fmt.Sprintf(`{"data":[{"type":"cluster","name":"lab","nodes":1,"quorate":1},{"type":"node","name":%q,"local":1,"online":1}]}`, node)
		},
		"/api2/json/cluster/resources": func() string {
			up := int(time.Since(started).Seconds()) + 86400
			return fmt.Sprintf(`{"data":[
 {"type":"lxc","vmid":101,"name":"nginx","node":%[1]q,"status":"running","maxcpu":2,"cpu":0.012,"mem":134217728,"maxmem":536870912,"disk":1073741824,"maxdisk":8589934592,"uptime":%[2]d,"template":0},
 {"type":"lxc","vmid":102,"name":"postgres","node":%[1]q,"status":"running","maxcpu":4,"cpu":0.31,"mem":3221225472,"maxmem":4294967296,"disk":21474836480,"maxdisk":34359738368,"uptime":%[2]d,"template":0},
 {"type":"qemu","vmid":110,"name":"app-server","node":%[1]q,"status":"running","maxcpu":4,"cpu":0.125,"mem":2147483648,"maxmem":8589934592,"disk":0,"maxdisk":53687091200,"uptime":%[2]d,"template":0},
 {"type":"lxc","vmid":115,"name":"ocrmypdf","node":%[1]q,"status":"stopped","maxcpu":1,"cpu":0,"mem":0,"maxmem":536870912,"disk":0,"maxdisk":8589934592,"uptime":0,"template":0},
 {"type":"qemu","vmid":900,"name":"debian-template","node":%[1]q,"status":"stopped","maxcpu":2,"template":1},
 {"type":"storage","storage":"local","node":%[1]q,"status":"available","plugintype":"dir","disk":42949672960,"maxdisk":107374182400},
 {"type":"storage","storage":"local-zfs","node":%[1]q,"status":"available","plugintype":"zfspool","disk":429496729600,"maxdisk":483183820800},
 {"type":"storage","storage":"nas-backup","node":%[1]q,"status":"unknown","plugintype":"nfs","disk":0,"maxdisk":0}
]}`, node, up)
		},
	}
	lxcIfs := map[string]string{
		"101": `{"data":[{"name":"lo","inet":"127.0.0.1/8","inet6":"::1/128"},{"name":"eth0","inet":"192.168.10.21/24","inet6":"fe80::1/64"}]}`,
		"102": `{"data":[{"name":"lo","inet":"127.0.0.1/8"},{"name":"eth0","inet":"192.168.10.22/24"}]}`,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PVEAPIToken="+*token {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if f, ok := replies[r.URL.Path]; ok {
			fmt.Fprint(w, f())
			return
		}
		// /nodes/<node>/lxc/<id>/interfaces
		if parts := strings.Split(r.URL.Path, "/"); len(parts) == 8 && parts[5] == "lxc" && parts[7] == "interfaces" {
			if body, ok := lxcIfs[parts[6]]; ok {
				fmt.Fprint(w, body)
				return
			}
		}
		// Like a real node without a guest agent in the VM.
		http.Error(w, `{"data":null,"message":"QEMU guest agent is not running"}`, http.StatusInternalServerError)
	})
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	log.Printf("fakepve: stand-in Proxmox API on https://%s for node %q", *listen, node)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
