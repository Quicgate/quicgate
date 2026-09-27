package docker

import (
	"strings"
	"testing"
)

// The endpoint list is decoded strictly: a misspelt field is refused rather
// than ignored (a misspelt caFile would turn a TLS endpoint into a plaintext
// one), missing fields take the local defaults, and every entry is validated.
func TestParseEndpointsStrictAndValidated(t *testing.T) {
	eps, err := ParseEndpoints(`[
		{"name": "local"},
		{"name": "docker92", "connect": "tcp://192.168.1.92:2375", "address": "192.168.1.92"},
		{"connect": "https://docker93.lan:2376", "address": "docker93.lan", "caFile": "/etc/qg/ca.pem", "certFile": "/etc/qg/cert.pem", "keyFile": "/etc/qg/key.pem"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 3 || eps[0].Connect != "/var/run/docker.sock" || eps[0].Address != "127.0.0.1" || eps[2].Name != "endpoint3" {
		t.Fatalf("defaults not applied: %+v", eps)
	}
	if !eps[2].tls() || eps[1].tls() {
		t.Fatalf("tls flags: %+v", eps)
	}
	// Go matches JSON field names without regard to case, so "cafile" is
	// caFile, not an unknown field; a different spelling is.
	if eps, err := ParseEndpoints(`[{"name":"x","connect":"tcp://h:2376","address":"h","cafile":"/ca.pem"}]`); err != nil || eps[0].CAFile != "/ca.pem" {
		t.Fatalf("cafile: %+v %v", eps, err)
	}

	for name, c := range map[string]struct{ raw, reason string }{
		"unknown field":          {`[{"name":"x","connect":"tcp://h:2375","adress":"1.2.3.4"}]`, "adress"},
		"misspelt TLS field":     {`[{"name":"x","connect":"tcp://h:2375","address":"1.2.3.4","ca_file":"/ca.pem"}]`, "ca_file"},
		"not a list":             {`{"name":"x"}`, "docker_endpoints"},
		"empty list":             {`[]`, "empty"},
		"text after the list":    {`[{"name":"x"}] trailing`, "after the list"},
		"connect without port":   {`[{"name":"x","connect":"tcp://192.168.1.9","address":"192.168.1.9"}]`, "host:port"},
		"connect port range":     {`[{"name":"x","connect":"tcp://192.168.1.9:70000","address":"192.168.1.9"}]`, "out of range"},
		"connect odd scheme":     {`[{"name":"x","connect":"ssh://192.168.1.9:22","address":"192.168.1.9"}]`, "unix socket path, tcp://host:port or https://host:port"},
		"connect relative path":  {`[{"name":"x","connect":"docker.sock","address":"127.0.0.1"}]`, "unix socket path"},
		"connect host with path": {`[{"name":"x","connect":"tcp://192.168.1.9:2375/v1.41","address":"192.168.1.9"}]`, "not a number"},
		"address not a host":     {`[{"name":"x","connect":"tcp://192.168.1.9:2375","address":"192.168.1.9; rm -rf"}]`, "address"},
		"address with port":      {`[{"name":"x","connect":"tcp://192.168.1.9:2375","address":"192.168.1.9:80"}]`, "address"},
		"TLS files on a socket":  {`[{"name":"x","connect":"/var/run/docker.sock","address":"127.0.0.1","caFile":"/ca.pem"}]`, "unix socket"},
		"TLS files on http":      {`[{"name":"x","connect":"http://h:2375","address":"h","caFile":"/ca.pem"}]`, "not http://"},
		"cert without key":       {`[{"name":"x","connect":"tcp://h:2376","address":"h","certFile":"/c.pem"}]`, "go together"},
		"duplicate names":        {`[{"name":"x","connect":"tcp://h:2375","address":"h"},{"name":"x","connect":"tcp://h:2376","address":"h"}]`, "two entries are named"},
	} {
		_, err := ParseEndpoints(c.raw)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: got %v, want an error mentioning %q", name, err, c.reason)
		}
	}
}

func TestValidHost(t *testing.T) {
	for _, ok := range []string{"127.0.0.1", "::1", "docker92", "docker92.lan", "socket_proxy", "a.b-c.example.com.", "2001:db8::1"} {
		if !validHost(ok) {
			t.Errorf("%q should be a valid host", ok)
		}
	}
	long := strings.Repeat("a", 64)
	for _, bad := range []string{"", " ", "host name", "-lead.example", "trail-.example", "a..b", long + ".example", "http://x", "x/y", "1.2.3.4:80"} {
		if validHost(bad) {
			t.Errorf("%q should not be a valid host", bad)
		}
	}
}
