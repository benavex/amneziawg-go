/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Exported GSO/GRO API expected by Tailscale's fork of this package.
 *
 * Tailscale's wireguard-go fork (github.com/tailscale/wireguard-go) exports a
 * set of GSO (Generic Segmentation Offload) types and helpers on top of the
 * internal GRO/GSO machinery in offload_linux.go. This file provides the same
 * public surface for amneziawg-go so tailscale.com builds against it
 * unmodified.
 *
 * The types here mirror those in upstream wireguard-go's tun package.
 */

package tun

// GSOType describes the kind of Generic Segmentation Offload applied to a
// packet. It mirrors Linux's VIRTIO_NET_HDR_GSO_* constants but uses Go
// typing.
type GSOType uint8

const (
	// GSONone indicates the packet is not segmentation-offloaded.
	GSONone GSOType = iota
	// GSOTCPv4 indicates TCP over IPv4 with GSO.
	GSOTCPv4
	// GSOTCPv6 indicates TCP over IPv6 with GSO.
	GSOTCPv6
	// GSOUDPL4 indicates UDP with GSO (segmenting a large UDP datagram into
	// smaller ones — Linux's UDP_L4 GSO).
	GSOUDPL4
)

// GSOOptions describes segmentation/checksum metadata for a packet passed to
// GSOSplit. It mirrors the fields upstream wireguard-go exposes via its own
// GSOOptions type and uses the same semantics as Linux's virtio_net_hdr.
type GSOOptions struct {
	// GSOType is the type of segmentation offload being applied.
	GSOType GSOType
	// HdrLen is the combined L3+L4 header length in bytes.
	HdrLen uint16
	// CsumStart is the offset into the packet where checksum computation
	// starts (typically the L4 header offset).
	CsumStart uint16
	// CsumOffset is the offset within the L4 header where the checksum is
	// written, relative to CsumStart.
	CsumOffset uint16
	// GSOSize is the maximum segment size (excluding headers).
	GSOSize uint16
	// NeedsCsum indicates whether the stack must finalize the transport
	// checksum.
	NeedsCsum bool
}

// GSOSplit segments pkt (a GSO "super-packet" described by opts) into
// individual MSS-sized packets written into outBuffs starting at offset.
// It returns the number of packets produced and any error. sizes[i] receives
// the payload length of outBuffs[i].
//
// With GSOType == GSONone the packet is copied as-is (single segment).
//
// This implementation is a thin wrapper around the existing internal
// GSO/segmentation logic in offload_linux.go. At present it handles the
// GSONone case directly; the TCP/UDP L4 cases are stubbed and return an
// error. Tailscale only uses GSOSplit from the netstack injection path
// which is disabled in our builds (ts_omit_netstack).
//
// TODO(vpn-mesh): wire up real segmentation by exporting or refactoring
// the existing handleGRO / virtioNetHdr.encode paths in offload_linux.go
// once Phase 1 is stable.
func GSOSplit(pkt []byte, opts GSOOptions, outBuffs [][]byte, sizes []int, offset int) (int, error) {
	if opts.GSOType == GSONone {
		if len(outBuffs) == 0 || len(sizes) == 0 {
			return 0, errGSONoBufs
		}
		if offset+len(pkt) > len(outBuffs[0]) {
			return 0, errGSOBufTooSmall
		}
		n := copy(outBuffs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
	return 0, errGSOUnsupported
}

// GRODevice is the interface implemented by TUN devices that can have their
// kernel-side TCP/UDP GRO (Generic Receive Offload) toggled at runtime.
// Tailscale type-asserts a *tun.Device to this interface in its Linux code
// path.
type GRODevice interface {
	// Write writes one or more packets to the device. Matches tun.Device.Write.
	Write(bufs [][]byte, offset int) (int, error)
	// DisableUDPGRO disables UDP GRO on the device's kernel-facing socket.
	DisableUDPGRO()
	// DisableTCPGRO disables TCP GRO on the device's kernel-facing socket.
	DisableTCPGRO()
}

// Static errors for GSOSplit.
var (
	errGSONoBufs      = gsoError("tun.GSOSplit: empty output buffers")
	errGSOBufTooSmall = gsoError("tun.GSOSplit: output buffer too small")
	errGSOUnsupported = gsoError("tun.GSOSplit: GSOType not implemented in amneziawg-go wrapper; this path is only reachable with netstack, which is disabled")
)

type gsoError string

func (e gsoError) Error() string { return string(e) }
