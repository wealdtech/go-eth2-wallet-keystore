// Copyright 2024 Weald Technology Trading.
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
	"encoding/hex"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

// MarshalJSON implements custom JSON marshaller.
func (a *account) MarshalJSON() ([]byte, error) {
	data := make(map[string]any)
	data["uuid"] = a.id.String()
	data["description"] = a.name
	data["pubkey"] = hex.EncodeToString(a.publicKey.Marshal())
	data["crypto"] = a.crypto
	data["version"] = a.version

	return json.Marshal(data)
}

// UnmarshalJSON implements custom JSON unmarshaller.
//
//nolint:cyclop,funlen
func (a *account) UnmarshalJSON(data []byte) error {
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, "failed to unmarshal account")
	}
	if val, exists := v["uuid"]; exists {
		idStr, ok := val.(string)
		if !ok {
			return errors.New("account ID invalid")
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return errors.Wrap(err, "failed to parse account ID")
		}

		a.id = id
	} else {
		return errors.New("account ID missing")
	}

	// Store description as name, if present.
	if val, exists := v["description"]; exists {
		description, ok := val.(string)
		if !ok {
			return errors.New("account description invalid")
		}
		a.name = description
	}

	if val, exists := v["pubkey"]; exists {
		publicKey, ok := val.(string)
		if !ok {
			return errors.New("account pubkey invalid")
		}
		bytes, err := hex.DecodeString(publicKey)
		if err != nil {
			return errors.Wrap(err, "failed to decode public key")
		}
		a.publicKey, err = e2types.BLSPublicKeyFromBytes(bytes)
		if err != nil {
			return errors.Wrap(err, "invalid public key")
		}
	} else {
		return errors.New("account pubkey missing")
	}
	if val, exists := v["crypto"]; exists {
		crypto, ok := val.(map[string]any)
		if !ok {
			return errors.New("account crypto invalid")
		}
		a.crypto = crypto
	} else {
		return errors.New("account crypto missing")
	}
	if val, exists := v["version"]; exists {
		version, ok := val.(float64)
		if !ok {
			return errors.New("account version invalid")
		}
		a.version = uint(version)
	} else {
		return errors.New("account version missing")
	}
	// Only support keystore v4 at current.
	if a.version != 4 {
		return errors.New("unsupported keystore version")
	}

	// Keystore does not support different encryptors; use default.
	a.encryptor = keystorev4.New()

	return nil
}
