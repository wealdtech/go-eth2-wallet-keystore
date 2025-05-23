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

// Package keystore is a wallet with keys in keystore format, where each key
// is created from random bytes.
package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/wealdtech/go-ecodec"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

const (
	walletType = "keystore"
	version    = 1
)

// wallet contains the details of the wallet.
type wallet struct {
	id             uuid.UUID
	name           string
	version        uint
	store          e2wtypes.Store
	encryptor      e2wtypes.Encryptor
	unlocked       bool
	batch          *batch
	accounts       map[uuid.UUID]*account
	mutex          sync.Mutex
	batchMutex     sync.Mutex
	batchDecrypted bool
}

// newWallet creates a new wallet.
func newWallet() *wallet {
	return &wallet{
		accounts: make(map[uuid.UUID]*account),
	}
}

// CreateWallet creates a new wallet with the given name and stores it in the provided store.
// This will error if the wallet already exists.
func CreateWallet(ctx context.Context, name string, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	// First, try to open the wallet.
	_, err := OpenWallet(ctx, name, store, encryptor)
	if err == nil || !strings.Contains(err.Error(), "wallet not found") {
		return nil, fmt.Errorf("wallet %q already exists", name)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate UUID")
	}

	w := newWallet()
	w.id = id
	w.name = name
	w.version = version
	w.store = store
	w.encryptor = encryptor

	return w, w.storeWallet()
}

// OpenWallet opens an existing wallet with the given name.
func OpenWallet(ctx context.Context, name string, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	data, err := store.RetrieveWallet(name)
	if err != nil {
		return nil, errors.Wrapf(err, "wallet %q does not exist", name)
	}

	return DeserializeWallet(ctx, data, store, encryptor)
}

// DeserializeWallet deserializes a wallet from its byte-level representation.
func DeserializeWallet(_ context.Context,
	data []byte,
	store e2wtypes.Store,
	encryptor e2wtypes.Encryptor,
) (
	e2wtypes.Wallet,
	error,
) {
	wallet := newWallet()
	if err := json.Unmarshal(data, wallet); err != nil {
		return nil, errors.Wrap(err, "wallet corrupt")
	}
	wallet.store = store
	wallet.encryptor = encryptor

	return wallet, nil
}

// ID provides the ID for the wallet.
func (w *wallet) ID() uuid.UUID {
	return w.id
}

// Type provides the type for the wallet.
func (w *wallet) Type() string {
	return walletType
}

// Name provides the name for the wallet.
func (w *wallet) Name() string {
	return w.name
}

// Version provides the version of the wallet.
func (w *wallet) Version() uint {
	return w.version
}

// Lock locks the wallet.  A locked wallet cannot create new accounts.
func (w *wallet) Lock(_ context.Context) error {
	w.unlocked = false

	return nil
}

// Unlock unlocks the wallet.  An unlocked wallet can create new accounts.
func (w *wallet) Unlock(_ context.Context, _ []byte) error {
	w.unlocked = true

	return nil
}

// IsUnlocked reports if the wallet is unlocked.
func (w *wallet) IsUnlocked(_ context.Context) (bool, error) {
	return w.unlocked, nil
}

// storeWallet stores the wallet in the store.
func (w *wallet) storeWallet() error {
	data, err := json.Marshal(w)
	if err != nil {
		return errors.Wrap(err, "failed to marshal wallet")
	}

	return w.store.StoreWallet(w.ID(), w.Name(), data)
}

// CreateAccount creates a new account in the wallet.
// The only rule for names is that they cannot start with an underscore (_) character.
func (w *wallet) CreateAccount(ctx context.Context, name string, passphrase []byte) (e2wtypes.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if !w.unlocked {
		return nil, errors.New("wallet must be unlocked to create accounts")
	}

	// Ensure that we don't already have an account with this name
	if _, err := w.AccountByName(ctx, name); err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	var err error
	if a.id, err = uuid.NewRandom(); err != nil {
		return nil, err
	}
	a.name = name
	privateKey, err := e2types.GenerateBLSPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate private key")
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key.
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), string(passphrase))
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt private key")
	}
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	w.mutex.Lock()
	if err := a.storeAccount(ctx); err != nil {
		w.mutex.Unlock()

		return nil, err
	}
	w.accounts[a.id] = a
	w.mutex.Unlock()

	return a, nil
}

// ImportAccount creates a new account in the wallet from an existing private key.
// The only rule for names is that they cannot start with an underscore (_) character.
// This will error if an account with the name already exists.
func (w *wallet) ImportAccount(ctx context.Context, name string, key []byte, passphrase []byte) (e2wtypes.Account, error) {
	if name == "" {
		return nil, errors.New("account name missing")
	}
	if strings.HasPrefix(name, "_") {
		return nil, fmt.Errorf("invalid account name %q", name)
	}
	if !w.unlocked {
		return nil, errors.New("wallet must be unlocked to import accounts")
	}

	// Ensure that we don't already have an account with this name.
	_, err := w.AccountByName(ctx, name)
	if err == nil {
		return nil, fmt.Errorf("account with name %q already exists", name)
	}

	a := newAccount()
	a.id, err = uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate UUID")
	}
	a.name = name
	privateKey, err := e2types.BLSPrivateKeyFromBytes(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode private key")
	}
	a.publicKey = privateKey.PublicKey()
	// Encrypt the private key.
	a.crypto, err = w.encryptor.Encrypt(privateKey.Marshal(), string(passphrase))
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt private key")
	}
	a.encryptor = w.encryptor
	a.version = w.encryptor.Version()
	a.wallet = w

	// Have to update the index first so that storeAccount() stores the
	// index with the new account present, but be ready to revert if it fails.
	w.mutex.Lock()
	if err := a.storeAccount(ctx); err != nil {
		w.mutex.Unlock()

		return nil, err
	}
	w.accounts[a.id] = a
	w.mutex.Unlock()

	return a, nil
}

func (w *wallet) retrieveBatchIfRequired(ctx context.Context) error {
	var err error

	if !w.batchPresent() {
		// Batch not retrieved, try to retrieve it now.
		if _, isBatchRetriever := w.store.(e2wtypes.BatchRetriever); isBatchRetriever {
			err = w.retrieveAccountsBatch(ctx)
		}
	}

	return err
}

// Accounts provides all accounts in the wallet.
func (w *wallet) Accounts(ctx context.Context) <-chan e2wtypes.Account {
	ch := make(chan e2wtypes.Account, 1024)

	go func(ch chan e2wtypes.Account) {
		_ = w.retrieveBatchIfRequired(ctx)

		if w.batchPresent() {
			// Batch present, use pre-loaded accounts.
			for _, account := range w.accounts {
				ch <- account
			}
			close(ch)

			return
		}

		// No batch; fall back to individual accounts on the store.
		for data := range w.store.RetrieveAccounts(w.ID()) {
			if account, err := deserializeAccount(w, data); err == nil {
				ch <- account
			}
		}
		close(ch)
	}(ch)

	return ch
}

// Export exports the entire wallet, protected by an additional passphrase.
func (w *wallet) Export(ctx context.Context, passphrase []byte) ([]byte, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	accounts := make([]*account, 0)
	for data := range w.store.RetrieveAccounts(w.ID()) {
		account, err := deserializeAccount(w, data)
		if err != nil {
			return nil, errors.Wrap(err, " failed to deserialize account")
		}
		accounts = append(accounts, account)
	}

	ext := &walletExt{
		Wallet:   w,
		Accounts: accounts,
	}

	data, err := json.Marshal(ext)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal wallet for export")
	}

	res, err := ecodec.Encrypt(data, passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt export")
	}

	return res, nil
}

// Import imports the entire wallet, protected by an additional passphrase.
func Import(ctx context.Context,
	encryptedData []byte,
	passphrase []byte,
	store e2wtypes.Store,
	encryptor e2wtypes.Encryptor,
) (
	e2wtypes.Wallet,
	error,
) {
	type walletExt struct {
		Wallet   *wallet    `json:"wallet"`
		Accounts []*account `json:"accounts"`
	}

	data, err := ecodec.Decrypt(encryptedData, passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt wallet")
	}

	//  Create the wallet.
	ext := &walletExt{
		Wallet: newWallet(),
	}
	ext.Wallet.store = store
	ext.Wallet.encryptor = encryptor
	if err := json.Unmarshal(data, ext); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal wallet")
	}

	// See if the wallet already exists.
	if _, err := OpenWallet(ctx, ext.Wallet.Name(), store, encryptor); err == nil {
		return nil, fmt.Errorf("wallet %q already exists", ext.Wallet.Name())
	}

	// Store the wallet.
	if err := ext.Wallet.storeWallet(); err != nil {
		return nil, errors.Wrapf(err, "failed to store wallet %q", ext.Wallet.Name())
	}

	// Create the accounts.
	for _, acc := range ext.Accounts {
		acc.wallet = ext.Wallet
		acc.encryptor = encryptor
		if err := acc.storeAccount(ctx); err != nil {
			return nil, errors.Wrapf(err, "failed to store account %q", acc.Name())
		}
	}

	return ext.Wallet, nil
}

// AccountByName provides a single account from the wallet given its name.
// This will error if the account is not found.
func (w *wallet) AccountByName(ctx context.Context, name string) (e2wtypes.Account, error) {
	_ = w.retrieveBatchIfRequired(ctx)

	if w.batchPresent() {
		// Batch present, use pre-loaded account if available.
		for _, account := range w.accounts {
			if account.name == name {
				return account, nil
			}
		}
	}

	// No batch or account not in batch; fall back to individual accounts on the store.
	for data := range w.store.RetrieveAccounts(w.id) {
		account, err := deserializeAccount(w, data)
		if err != nil {
			return nil, err
		}
		if account.name == name {
			return account, nil
		}
	}

	return nil, fmt.Errorf("no account with name %q", name)
}

// AccountByID provides a single account from the wallet given its ID.
// This will error if the account is not found.
func (w *wallet) AccountByID(ctx context.Context, id uuid.UUID) (e2wtypes.Account, error) {
	_ = w.retrieveBatchIfRequired(ctx)

	if w.batchPresent() {
		// Batch present, use pre-loaded account if available.
		if account, exists := w.accounts[id]; exists {
			return account, nil
		}
	}

	// No batch or account not in batch; fall back to individual account on the store.
	data, err := w.store.RetrieveAccount(w.id, id)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve account")
	}
	res, err := deserializeAccount(w, data)
	if err != nil {
		return nil, err
	}
	w.accounts[id] = res

	return res, nil
}

// Store returns the wallet's store.
func (w *wallet) Store() e2wtypes.Store {
	return w.store
}
