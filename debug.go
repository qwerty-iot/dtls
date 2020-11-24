// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

var DebugHandshake bool = false
var DebugHandshakeHash bool = false
var DebugEncryption bool = false

func DebugAll() {
	DebugHandshake = true
	DebugHandshakeHash = true
	DebugEncryption = true
}
