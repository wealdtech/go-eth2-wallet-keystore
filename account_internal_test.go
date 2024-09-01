// Copyright © 2024 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keystore

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestUnmarshalAccount(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		err        error
		id         uuid.UUID
		version    uint
		walletType string
		publicKey  []byte
	}{
		{
			name: "Nil",
			err:  errors.New("unexpected end of JSON input"),
		},
		{
			name:  "Empty",
			input: []byte{},
			err:   errors.New("unexpected end of JSON input"),
		},
		{
			name:  "Blank",
			input: []byte(""),
			err:   errors.New("unexpected end of JSON input"),
		},
		{
			name:  "NotJSON",
			input: []byte(`bad`),
			err:   errors.New(`invalid character 'b' looking for beginning of value`),
		},
		{
			name:       "Good",
			input:      []byte(`{"crypto":{"checksum":{"function":"sha256","message":"834042b7466d411229671f2bab77a3ce92cf899fb0a187c6f1b33833e94c6311","params":{}},"cipher":{"function":"aes-128-ctr","message":"3f721459224dd5cfc0a350a6ae74160daa775fe1b25a301f572ef817beb9c9c0","params":{"iv":"cfb0d03016d09ba21106151eb9819f56"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ec4d0397897713740f27a79911a03feb11d1c70346f90867cfc0e64aee4983e7"}}},"description":"0640","pubkey":"b991005d3c71ed6deb6a44e99980afcc81d660cbdb29695acd2f519a364a80f03de1fa42eac312704f8c25ec5657b958","uuid":"a7bb9f4d-3877-4b52-af67-97aa943073a5","version":4}`),
			walletType: "keystore",
			id:         uuid.MustParse("a7bb9f4d-3877-4b52-af67-97aa943073a5"),
			publicKey:  []byte{0xb9, 0x91, 0x00, 0x5d, 0x3c, 0x71, 0xed, 0x6d, 0xeb, 0x6a, 0x44, 0xe9, 0x99, 0x80, 0xaf, 0xcc, 0x81, 0xd6, 0x60, 0xcb, 0xdb, 0x29, 0x69, 0x5a, 0xcd, 0x2f, 0x51, 0x9a, 0x36, 0x4a, 0x80, 0xf0, 0x3d, 0xe1, 0xfa, 0x42, 0xea, 0xc3, 0x12, 0x70, 0x4f, 0x8c, 0x25, 0xec, 0x56, 0x57, 0xb9, 0x58},
			version:    4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := newAccount()
			err := json.Unmarshal(test.input, output)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				assert.Equal(t, test.id, output.ID())
				assert.Equal(t, test.publicKey, output.PublicKey().Marshal())
				assert.Equal(t, test.version, output.version)
				assert.Equal(t, test.walletType, output.wallet.Type())
			}
		})
	}
}

func TestUnlock(t *testing.T) {
	tests := []struct {
		name       string
		account    []byte
		passphrase []byte
		err        error
	}{
		{
			name:       "PublicKeyMismatch",
			account:    []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"b89bebc699769726a318c8e9971bd3171297c61aea4a6578a7a4f94b547dcba5bac16a89108b6b6a1fe3695d1a874a0b","version":4,"crypto":{"checksum":{"function":"sha256","message":"09b65fda487a021900003a8b2081694b15ca73e0e59a5c79a5126f6818a2f171","params":{}},"cipher":{"function":"aes-128-ctr","message":"8386db98fbe002c02de9bc122b7680078045bf6c5c9ac2f7e8b53afbea0d3e15","params":{"iv":"45092570c625ad5e8decfcd991464740"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"ae6433afd822e6d99dfaa1a0d73d2ee263efdf62f858ba0c422cf27982d09c8a"}}}}`),
			passphrase: []byte("test passphrase"),
			err:        errors.New("private key does not correspond to public key"),
		},
		{
			name:       "Keystore",
			account:    []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4,"crypto":{"checksum":{"function":"sha256","message":"09b65fda487a021900003a8b2081694b15ca73e0e59a5c79a5126f6818a2f171","params":{}},"cipher":{"function":"aes-128-ctr","message":"8386db98fbe002c02de9bc122b7680078045bf6c5c9ac2f7e8b53afbea0d3e15","params":{"iv":"45092570c625ad5e8decfcd991464740"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"ae6433afd822e6d99dfaa1a0d73d2ee263efdf62f858ba0c422cf27982d09c8a"}}}}`),
			passphrase: []byte("test passphrase"),
		},
		{
			name:       "BadPassphrase",
			account:    []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4,"crypto":{"checksum":{"function":"sha256","message":"09b65fda487a021900003a8b2081694b15ca73e0e59a5c79a5126f6818a2f171","params":{}},"cipher":{"function":"aes-128-ctr","message":"8386db98fbe002c02de9bc122b7680078045bf6c5c9ac2f7e8b53afbea0d3e15","params":{"iv":"45092570c625ad5e8decfcd991464740"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"ae6433afd822e6d99dfaa1a0d73d2ee263efdf62f858ba0c422cf27982d09c8a"}}}}`),
			passphrase: []byte("wrong passphrase"),
			err:        errors.New("incorrect passphrase"),
		},
		{
			name:       "EmptyPassphrase",
			account:    []byte(`{"uuid":"c9958061-63d4-4a80-bcf3-25f3dda22340","name":"test account","pubkey":"a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c","version":4,"crypto":{"checksum":{"function":"sha256","message":"4a67cc6a4ff5e81235393c677652213cc96488d68f17d045f99f9cef8acc81a1","params":{}},"cipher":{"function":"aes-128-ctr","message":"ce7c1d11cd71adb604c055a2d198336387e0579275c4d2d45c184ed54631ebdd","params":{"iv":"c752efc43ca0651bb06adccf4b8651b8"}},"kdf":{"function":"pbkdf2","message":"","params":{"c":16,"dklen":32,"prf":"hmac-sha256","salt":"b49107e74e59a80ce5ac1624e6d27e7305aa22f5ffba4f602dd4dfe34fdf8640"}}}}`),
			passphrase: []byte(""),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			account := newAccount()
			err := json.Unmarshal(test.account, account)
			require.Nil(t, err)

			// Try to sign something - should fail because locked
			_, err = account.Sign(context.Background(), []byte("test"))
			assert.NotNil(t, err)

			err = account.Unlock(context.Background(), test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)

				// Try to sign something - should succeed because unlocked
				signature, err := account.Sign(context.Background(), []byte("test"))
				assert.Nil(t, err)

				verified := signature.Verify([]byte("test"), account.PublicKey())
				assert.Equal(t, true, verified)

				require.NoError(t, account.Lock(context.Background()))

				// Try to sign something - should fail because locked (again)
				_, err = account.Sign(context.Background(), []byte("test"))
				assert.NotNil(t, err)
			}
		})
	}
}
