package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportOmitsAbsentFields(t *testing.T) {
	b, err := json.Marshal(Report{ProtocolVersion: Version, AgentVersion: "0.1.0", TS: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cpu_pct", "inventory", "mem", "disks"} {
		if strings.Contains(string(b), key) {
			t.Errorf("absent field %q was serialized: %s", key, b)
		}
	}
}

func TestReportDecodesSpecExample(t *testing.T) {
	const in = `{"protocol_version":1,"agent_version":"0.1.0","ts":1790944200,
	 "metrics":{"cpu_pct":14.2,"load":[0.42,0.31,0.20],"uptime_s":3628800,
	  "mem":{"total":34359738368,"used":20186346291,"available":14173392077},
	  "swap":{"total":8589934592,"used":0},
	  "disks":[{"mount":"/","fs":"ext4","total":1000204886016,"used":651882332160}],
	  "net":[{"name":"eno1","state":"up","rx_bytes":5,"tx_bytes":7}]},
	 "inventory":{"hostname":"web-01","os":"Debian 12","kernel":"6.1.0","cpu_model":"x","cores":8,
	  "interfaces":[{"name":"eno1","default_route":true,"ipv4":["192.168.10.10"],"ipv6":[]}]}}`
	var r Report
	if err := json.Unmarshal([]byte(in), &r); err != nil {
		t.Fatal(err)
	}
	if r.Metrics.CPUPct == nil || *r.Metrics.CPUPct != 14.2 {
		t.Errorf("cpu_pct = %v", r.Metrics.CPUPct)
	}
	if r.Metrics.Mem.Used != 20186346291 || r.Metrics.Disks[0].Mount != "/" || r.Metrics.Net[0].TxBytes != 7 {
		t.Errorf("metrics decoded wrong: %+v", r.Metrics)
	}
	if r.Inventory == nil || !r.Inventory.Interfaces[0].DefaultRoute || r.Inventory.Interfaces[0].IPv4[0] != "192.168.10.10" {
		t.Errorf("inventory decoded wrong: %+v", r.Inventory)
	}
}
