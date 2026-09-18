package wg

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
)

// never lists the ranges a site may not claim (S4).
var never = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ValidKey reports whether b64 is a usable WireGuard public or preshared key:
// 32 bytes of base64, and not all zero.
func ValidKey(b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("a WireGuard key is 32 bytes in base64")
	}
	for _, c := range raw {
		if c != 0 {
			return nil
		}
	}
	return fmt.Errorf("the all-zero key is not a key")
}

// TunnelAddress returns quicgate's own address: the first host of the prefix.
func TunnelAddress(tunnel netip.Prefix) netip.Addr { return tunnel.Masked().Addr().Next() }

// ValidateSite checks one site against the tunnel network, the server's own
// public key, the other sites and the machine's own networks (S3, S4).
// ownNets are the subnets on this machine's interfaces; claiming one needs
// allowOwnOverlap, because traffic for it is only sent into the tunnel when an
// upstream names the site, and the operator should know that.
func ValidateSite(s Site, tunnel netip.Prefix, serverPublicKey string, others []Site, ownNets []netip.Prefix, allowOwnOverlap bool) error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("a site needs a name")
	}
	if err := ValidKey(s.PublicKey); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	if s.PublicKey == serverPublicKey {
		return fmt.Errorf("that is this server's own public key")
	}
	if err := ValidKey(s.PresharedKey); err != nil {
		return fmt.Errorf("preshared key: %w", err)
	}
	if !tunnel.IsValid() || !tunnel.Addr().Is4() {
		return fmt.Errorf("the tunnel network must be an IPv4 prefix")
	}
	if !s.Address.Is4() || !tunnel.Contains(s.Address) || s.Address == TunnelAddress(tunnel) || s.Address == tunnel.Masked().Addr() {
		return fmt.Errorf("the site's address %s must be a host inside %s other than quicgate's own", s.Address, tunnel)
	}
	if len(s.Networks) == 0 {
		return fmt.Errorf("a site needs at least one network it fronts")
	}
	if s.Keepalive < 0 || s.Keepalive > 3600 {
		return fmt.Errorf("keepalive is 0 to 3600 seconds")
	}
	for i, n := range s.Networks {
		if !n.IsValid() || !n.Addr().Is4() {
			return fmt.Errorf("network %s: only IPv4 prefixes are supported", n)
		}
		n = n.Masked()
		if n.Bits() == 0 {
			return fmt.Errorf("network %s: a site cannot claim the whole address space", n)
		}
		if n.Overlaps(tunnel) {
			return fmt.Errorf("network %s overlaps the tunnel network %s", n, tunnel)
		}
		for _, bad := range never {
			if n.Overlaps(bad) {
				return fmt.Errorf("network %s overlaps %s, which no site may claim", n, bad)
			}
		}
		for j, m := range s.Networks {
			if i != j && n.Overlaps(m.Masked()) {
				return fmt.Errorf("networks %s and %s of this site overlap", n, m)
			}
		}
		if !allowOwnOverlap {
			for _, own := range ownNets {
				if n.Overlaps(own) {
					return fmt.Errorf("network %s overlaps %s, a network this machine is on: confirm that this is intended", n, own)
				}
			}
		}
	}
	for _, o := range others {
		if o.ID == s.ID {
			continue
		}
		if o.PublicKey == s.PublicKey {
			return fmt.Errorf("site %q already uses this public key", o.Name)
		}
		if o.Address == s.Address {
			return fmt.Errorf("site %q already has the address %s", o.Name, s.Address)
		}
		if strings.EqualFold(o.Name, s.Name) {
			return fmt.Errorf("a site named %q already exists", o.Name)
		}
		for _, n := range s.Networks {
			for _, m := range o.Networks {
				if n.Masked().Overlaps(m.Masked()) {
					return fmt.Errorf("network %s overlaps %s of site %q", n, m, o.Name)
				}
			}
		}
	}
	return nil
}
