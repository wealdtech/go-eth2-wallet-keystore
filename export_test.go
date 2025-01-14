// Copyright © 2019 Weald Technology Trading
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

package keystore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	keystore "github.com/wealdtech/go-eth2-wallet-keystore"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestExportWallet(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()
	wallet, err := keystore.CreateWallet(context.Background(), "test wallet", store, encryptor)
	require.Nil(t, err)
	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	require.True(t, isLocker)
	err = locker.Unlock(context.Background(), []byte{})
	require.Nil(t, err)

	account1, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "Account 1", []byte{})
	require.Nil(t, err)
	account2, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(context.Background(), "Account 2", []byte{})
	require.Nil(t, err)

	dump, err := wallet.(e2wtypes.WalletExporter).Export(context.Background(), []byte("dump"))
	require.Nil(t, err)

	// Import it
	store2 := scratch.New()
	wallet2, err := keystore.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	require.Nil(t, err)

	// Confirm the accounts are present
	account1Present := false
	account2Present := false
	for account := range wallet2.Accounts(context.Background()) {
		if account.ID().String() == account1.ID().String() {
			account1Present = true
		}
		if account.ID().String() == account2.ID().String() {
			account2Present = true
		}
	}
	assert.True(t, account1Present && account2Present)

	// Try to import it again; should fail
	_, err = keystore.Import(context.Background(), dump, []byte("dump"), store2, encryptor)
	assert.NotNil(t, err)
}
