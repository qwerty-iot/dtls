package session

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bocajim/dtls/transport"
)

func TestNewClient(t *testing.T) {

	peer := NewClientSession(&transport.NilPeer{})
	peer.Client.Identity = "Identity"
	peer.Client.Random, _ = hex.DecodeString("00000001E68D63E65CDEF492AA9877330CA7EEB5C786487F31DAE89452104156")
	peer.Server.Identity = "Identity"
	peer.Server.Random, _ = hex.DecodeString("5823185CF999576643D2E838C4FCAEAC6AE89C12C9E25517D95FE115C50BF080")
	peer.Psk, _ = hex.DecodeString("0011223344")

	peer.InitKeyBlock()

	t.Logf("KeyBlock: %s", peer.KeyBlock.Print())

	if strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ClientWriteKey)) != "CE3DB22CD0931C3E752176B43EB1939A" {
		t.Errorf("ClientWriteKey mismatch [%X] != [CE3DB22CD0931C3E752176B43EB1939A]", peer.KeyBlock.ClientWriteKey)
	}
	if strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ServerWriteKey)) != "3501B84CF54E2654090E82ABEFCDCCBD" {
		t.Errorf("ServerWriteKey mismatch [%X] != [3501B84CF54E2654090E82ABEFCDCCBD]", peer.KeyBlock.ServerWriteKey)
	}
	if strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ClientIV)) != "F21CE4E5" {
		t.Errorf("ClientIV mismatch [%X] != [F21CE4E5]", peer.KeyBlock.ClientIV)
	}
	if strings.ToUpper(hex.EncodeToString(peer.KeyBlock.ServerIV)) != "235A077A" {
		t.Errorf("ServerIV mismatch [%X] != [235A077A]", peer.KeyBlock.ServerIV)
	}
}
