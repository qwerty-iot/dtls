// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

type Transport interface {
	Type() string
	Local() string
	Shutdown() error
	NewEndpoint(address string) TransportEndpoint
	ReadPacket() ([]byte, TransportEndpoint, error)
}

type TransportEndpoint interface {
	String() string
	WritePacket(data []byte) error
}
