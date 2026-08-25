// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

const (
	tlsRecordHeaderLen   = 5
	tlsHandshakeRecord   = 0x16
	maxTLSRecordLen      = 16384 // RFC 8446: max TLSPlaintext.length
	handshakeClientHello = 0x01
	extServerName        = 0x0000
	sniHostNameType      = 0x00
)

// parseSNI extracts the host_name from a TLS handshake message body. It is
// defensive: any malformed or truncated input yields "" rather than a panic.
func parseSNI(b []byte) string {
	if len(b) < 4 || b[0] != handshakeClientHello {
		return ""
	}
	p := b[4:] // skip handshake type (1) + length (3)

	// client_version (2) + random (32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]

	// legacy_session_id
	sid, ok := takeU8Vector(p)
	if !ok {
		return ""
	}
	p = sid

	// cipher_suites
	cs, ok := takeU16Vector(p)
	if !ok {
		return ""
	}
	p = cs

	// legacy_compression_methods
	cm, ok := takeU8Vector(p)
	if !ok {
		return ""
	}
	p = cm

	// extensions
	if len(p) < 2 {
		return ""
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return ""
	}
	p = p[:extLen]

	for len(p) >= 4 {
		etype := int(p[0])<<8 | int(p[1])
		elen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < elen {
			return ""
		}
		ext := p[:elen]
		p = p[elen:]
		if etype == extServerName {
			return parseServerNameList(ext)
		}
	}
	return ""
}

func parseServerNameList(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	q := ext[2:]
	if len(q) < listLen {
		return ""
	}
	q = q[:listLen]
	for len(q) >= 3 {
		nameType := q[0]
		nameLen := int(q[1])<<8 | int(q[2])
		q = q[3:]
		if len(q) < nameLen {
			return ""
		}
		name := q[:nameLen]
		q = q[nameLen:]
		if nameType == sniHostNameType {
			return string(name)
		}
	}
	return ""
}

// takeU8Vector consumes a 1-byte-length-prefixed vector and returns the rest.
func takeU8Vector(p []byte) ([]byte, bool) {
	if len(p) < 1 {
		return nil, false
	}
	n := int(p[0])
	p = p[1:]
	if len(p) < n {
		return nil, false
	}
	return p[n:], true
}

// takeU16Vector consumes a 2-byte-length-prefixed vector and returns the rest.
func takeU16Vector(p []byte) ([]byte, bool) {
	if len(p) < 2 {
		return nil, false
	}
	n := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < n {
		return nil, false
	}
	return p[n:], true
}
