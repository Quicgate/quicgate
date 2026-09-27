package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// sniMaxRecords bounds the TLS records peekSNI reads for one ClientHello. A
// ClientHello normally fits one record; a client with large key shares, or a
// middlebox, may split it over a few. Beyond this the peer is not talking TLS
// in any way worth waiting for.
const sniMaxRecords = 4

// peekSNI reads the TLS ClientHello from conn, extracts the SNI server name,
// and returns it along with the raw bytes consumed so they can be re-sent to
// the backend (passthrough). It reads whole records, as many as the ClientHello
// spans, and never past the record that completes it. The name comes back as
// the client sent it; callers normalise it for matching.
func peekSNI(conn net.Conn) (string, *bytes.Buffer, error) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buf := &bytes.Buffer{} // every byte read, for the backend
	var hs []byte          // the handshake message, joined across records
	for rec := 0; rec < sniMaxRecords; rec++ {
		// TLS record header: type(1) version(2) length(2).
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return "", nil, err
		}
		if hdr[0] != 0x16 { // handshake record
			return "", nil, errors.New("not a TLS handshake")
		}
		recLen := int(hdr[3])<<8 | int(hdr[4])
		if recLen < 1 || recLen > 16384 {
			return "", nil, errors.New("bad record length")
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", nil, err
		}
		buf.Write(hdr)
		buf.Write(body)
		hs = append(hs, body...)
		if len(hs) < 4 {
			continue // not even the handshake header yet
		}
		// Handshake header: type(1) length(3).
		if hs[0] != 0x01 {
			return "", nil, errors.New("first handshake message is not a ClientHello")
		}
		msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) >= 4+msgLen {
			return parseSNI(hs[:4+msgLen]), buf, nil
		}
	}
	return "", nil, fmt.Errorf("ClientHello spans more than %d records", sniMaxRecords)
}

// parseSNI walks a ClientHello handshake body and returns the server_name.
func parseSNI(b []byte) string {
	// Handshake header: type(1) length(3).
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	p := b[4:]
	// client_version(2) + random(32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]
	// session_id
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return ""
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return ""
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return ""
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return ""
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return ""
	}
	p = p[cmLen:]
	// extensions
	if len(p) < 2 {
		return ""
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extTotal {
		return ""
	}
	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		extLen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < extLen {
			return ""
		}
		if extType == 0x0000 { // server_name
			return parseServerNameExt(p[:extLen])
		}
		p = p[extLen:]
	}
	return ""
}

func parseServerNameExt(b []byte) string {
	// server_name_list length(2)
	if len(b) < 2 {
		return ""
	}
	listLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < listLen {
		return ""
	}
	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(b[1])<<8 | int(b[2])
		b = b[3:]
		if len(b) < nameLen {
			return ""
		}
		if nameType == 0x00 { // host_name
			return string(b[:nameLen])
		}
		b = b[nameLen:]
	}
	return ""
}
