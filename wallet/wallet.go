package wallet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	types2 "github.com/elastos/Elastos.ELA.SideChain.ID/types"
	"github.com/elastos/Elastos.ELA.SideChain.ID/types/base64url"
	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/core/contract"
	"math"
	"math/rand"
	"strconv"

	"github.com/elastos/Elastos.ELA.Client.SideChain/log"

	"github.com/elastos/Elastos.ELA.SideChain/types"
	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/crypto"
)

const (
	DESTROY_ADDRESS = "0000000000000000000000000000000000"
)

var SystemAssetId = getSystemAssetId()

type Transfer struct {
	Address string
	Amount  *Fixed64
}

type CrossChainOutput struct {
	Address           string
	Amount            *Fixed64
	CrossChainAddress string
}

var wallet Wallet // Single instance of wallet

type Wallet interface {
	DataStore

	Open(name string, password []byte) error
	ChangePassword(oldPassword, newPassword []byte) error

	AddStandardAccount(publicKey *crypto.PublicKey) (*Uint168, error)
	AddMultiSignAccount(M int, publicKey ...*crypto.PublicKey) (*Uint168, error)

	CreateTransaction(fromAddress, toAddress string, amount, fee *Fixed64) (*types.Transaction, error)
	CreateLockedTransaction(fromAddress, toAddress string, amount, fee *Fixed64, lockedUntil uint32) (*types.Transaction, error)
	CreateMultiOutputTransaction(fromAddress string, fee *Fixed64, output ...*Transfer) (*types.Transaction, error)
	CreateLockedMultiOutputTransaction(fromAddress string, fee *Fixed64, lockedUntil uint32, output ...*Transfer) (*types.Transaction, error)
	CreateCrossChainTransaction(fromAddress, toAddress, crossChainAddress string, amount, fee *Fixed64) (*types.Transaction, error)
	CreateRegisterDIDTransaction(fromAddress string, fee *Fixed64) (*types.Transaction, error)

	Sign(name string, password []byte, transaction *types.Transaction) (*types.Transaction, error)

	Reset() error
}

type WalletImpl struct {
	DataStore
	Keystore
}

func Create(name string, password []byte) (*WalletImpl, error) {
	keyStore, err := CreateKeystore(name, password)
	if err != nil {
		log.Error("Wallet create key store failed:", err)
		return nil, err
	}

	dataStore, err := OpenDataStore()
	if err != nil {
		log.Error("Wallet create data store failed:", err)
		return nil, err
	}

	dataStore.AddAddress(keyStore.GetProgramHash(), keyStore.GetRedeemScript(), TypeMaster)

	return &WalletImpl{
		DataStore: dataStore,
		Keystore:  keyStore,
	}, nil
}

func GetWallet() (*WalletImpl, error) {
	dataStore, err := OpenDataStore()
	if err != nil {
		return nil, err
	}

	return &WalletImpl{
		DataStore: dataStore,
	}, nil
}

func (wallet *WalletImpl) Open(name string, password []byte) error {
	keyStore, err := OpenKeystore(name, password)
	if err != nil {
		return err
	}
	wallet.Keystore = keyStore
	return nil
}

func (wallet *WalletImpl) AddStandardAccount(publicKey *crypto.PublicKey) (*Uint168, error) {
	redeemScript, err := contract.CreateStandardRedeemScript(publicKey)
	if err != nil {
		return nil, errors.New("[Wallet], CreateStandardRedeemScript failed")
	}

	programHash := ToProgramHash(byte(contract.PrefixStandard), redeemScript)
	err = wallet.AddAddress(programHash, redeemScript, TypeStand)
	if err != nil {
		return nil, err
	}

	return programHash, nil
}

func (wallet *WalletImpl) AddMultiSignAccount(M int, publicKeys ...*crypto.PublicKey) (*Uint168, error) {
	redeemScript, err := contract.CreateMultiSigRedeemScript(M, publicKeys)
	if err != nil {
		return nil, errors.New("[Wallet], CreateStandardRedeemScript failed")
	}

	programHash := ToProgramHash(byte(contract.PrefixMultiSig), redeemScript)

	err = wallet.AddAddress(programHash, redeemScript, TypeMulti)
	if err != nil {
		return nil, err
	}

	return programHash, nil
}

func (wallet *WalletImpl) CreateTransaction(fromAddress, toAddress string, amount, fee *Fixed64) (*types.Transaction, error) {
	return wallet.CreateLockedTransaction(fromAddress, toAddress, amount, fee, uint32(0))
}

func (wallet *WalletImpl) CreateLockedTransaction(fromAddress, toAddress string, amount, fee *Fixed64, lockedUntil uint32) (*types.Transaction, error) {
	return wallet.CreateLockedMultiOutputTransaction(fromAddress, fee, lockedUntil, &Transfer{toAddress, amount})
}

func (wallet *WalletImpl) CreateMultiOutputTransaction(fromAddress string, fee *Fixed64, outputs ...*Transfer) (*types.Transaction, error) {
	return wallet.CreateLockedMultiOutputTransaction(fromAddress, fee, uint32(0), outputs...)
}

func (wallet *WalletImpl) CreateLockedMultiOutputTransaction(fromAddress string, fee *Fixed64, lockedUntil uint32, outputs ...*Transfer) (*types.Transaction, error) {
	return wallet.createTransaction(fromAddress, fee, lockedUntil, outputs...)
}

func (wallet *WalletImpl) CreateCrossChainTransaction(fromAddress, toAddress, crossChainAddress string, amount, fee *Fixed64) (*types.Transaction, error) {
	return wallet.createCrossChainTransaction(fromAddress, fee, uint32(0), &CrossChainOutput{toAddress, amount, crossChainAddress})
}

func (wallet *WalletImpl) createTransaction(fromAddress string, fee *Fixed64, lockedUntil uint32, outputs ...*Transfer) (*types.Transaction, error) {
	// Check if output is valid
	if len(outputs) == 0 {
		return nil, errors.New("[Wallet], Invalid transaction target")
	}
	// Sync chain block data before create transaction
	wallet.SyncChainData()

	// Check if from address is valid
	spender, err := Uint168FromAddress(fromAddress)
	if err != nil {
		return nil, errors.New(fmt.Sprint("[Wallet], Invalid spender address: ", fromAddress, ", error: ", err))
	}
	// Create transaction outputs
	var totalOutputAmount = Fixed64(0) // The total amount will be spend
	var txOutputs []*types.Output      // The outputs in transaction
	totalOutputAmount += *fee          // Add transaction fee

	for _, output := range outputs {
		receiver, err := Uint168FromAddress(output.Address)
		if err != nil {
			return nil, errors.New(fmt.Sprint("[Wallet], Invalid receiver address: ", output.Address, ", error: ", err))
		}
		txOutput := &types.Output{
			AssetID:     SystemAssetId,
			ProgramHash: *receiver,
			Value:       *output.Amount,
			OutputLock:  lockedUntil,
		}
		totalOutputAmount += *output.Amount
		txOutputs = append(txOutputs, txOutput)
	}
	// Get spender's UTXOs
	UTXOs, err := wallet.GetAddressUTXOs(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spender's UTXOs failed")
	}
	availableUTXOs := wallet.removeLockedUTXOs(UTXOs) // Remove locked UTXOs
	availableUTXOs = SortUTXOs(availableUTXOs)        // Sort available UTXOs by value ASC

	// Create transaction inputs
	var txInputs []*types.Input // The inputs in transaction
	for _, utxo := range availableUTXOs {
		input := &types.Input{
			Previous: types.OutPoint{
				TxID:  utxo.Op.TxID,
				Index: utxo.Op.Index,
			},
			Sequence: utxo.LockTime,
		}
		txInputs = append(txInputs, input)
		if *utxo.Amount < totalOutputAmount {
			totalOutputAmount -= *utxo.Amount
		} else if *utxo.Amount == totalOutputAmount {
			totalOutputAmount = 0
			break
		} else if *utxo.Amount > totalOutputAmount {
			change := &types.Output{
				AssetID:     SystemAssetId,
				Value:       *utxo.Amount - totalOutputAmount,
				OutputLock:  uint32(0),
				ProgramHash: *spender,
			}
			txOutputs = append(txOutputs, change)
			totalOutputAmount = 0
			break
		}
	}
	if totalOutputAmount > 0 {
		return nil, errors.New("[Wallet], Available token is not enough")
	}

	account, err := wallet.GetAddressInfo(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spenders account info failed")
	}

	return wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types.TransferAsset), nil
}

func (wallet *WalletImpl) createCrossChainTransaction(fromAddress string, fee *Fixed64, lockedUntil uint32, outputs ...*CrossChainOutput) (*types.Transaction, error) {
	// Check if output is valid
	if len(outputs) == 0 {
		return nil, errors.New("[Wallet], Invalid transaction target")
	}
	// Sync chain block data before create transaction
	wallet.SyncChainData()

	// Check if from address is valid
	spender, err := Uint168FromAddress(fromAddress)
	if err != nil {
		return nil, errors.New(fmt.Sprint("[Wallet], Invalid spender address: ", fromAddress, ", error: ", err))
	}
	// Create transaction outputs
	var totalOutputAmount = Fixed64(0) // The total amount will be spend
	var txOutputs []*types.Output      // The outputs in transaction
	totalOutputAmount += *fee          // Add transaction fee
	perAccountFee := *fee / Fixed64(len(outputs))

	txPayload := &types.PayloadTransferCrossChainAsset{}
	for index, output := range outputs {
		var receiver *Uint168
		if output.Address == DESTROY_ADDRESS {
			receiver = &Uint168{}
		} else {
			receiver, err = Uint168FromAddress(output.Address)
			if err != nil {
				return nil, errors.New(fmt.Sprint("[Wallet], Invalid receiver address: ", output.Address, ", error: ", err))
			}
		}
		txOutput := &types.Output{
			AssetID:     SystemAssetId,
			ProgramHash: *receiver,
			Value:       *output.Amount,
			OutputLock:  lockedUntil,
		}
		totalOutputAmount += *output.Amount
		txOutputs = append(txOutputs, txOutput)

		txPayload.CrossChainAddresses = append(txPayload.CrossChainAddresses, output.CrossChainAddress)
		txPayload.OutputIndexes = append(txPayload.OutputIndexes, uint64(index))
		txPayload.CrossChainAmounts = append(txPayload.CrossChainAmounts, *output.Amount-perAccountFee)
	}
	// Get spender's UTXOs
	UTXOs, err := wallet.GetAddressUTXOs(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spender's UTXOs failed")
	}
	availableUTXOs := wallet.removeLockedUTXOs(UTXOs) // Remove locked UTXOs
	availableUTXOs = SortUTXOs(availableUTXOs)        // Sort available UTXOs by value ASC

	// Create transaction inputs
	var txInputs []*types.Input // The inputs in transaction
	for _, utxo := range availableUTXOs {
		input := &types.Input{
			Previous: types.OutPoint{
				TxID:  utxo.Op.TxID,
				Index: utxo.Op.Index,
			},
			Sequence: utxo.LockTime,
		}
		txInputs = append(txInputs, input)
		if *utxo.Amount < totalOutputAmount {
			totalOutputAmount -= *utxo.Amount
		} else if *utxo.Amount == totalOutputAmount {
			totalOutputAmount = 0
			break
		} else if *utxo.Amount > totalOutputAmount {
			change := &types.Output{
				AssetID:     SystemAssetId,
				Value:       *utxo.Amount - totalOutputAmount,
				OutputLock:  uint32(0),
				ProgramHash: *spender,
			}
			txOutputs = append(txOutputs, change)
			totalOutputAmount = 0
			break
		}
	}
	if totalOutputAmount > 0 {
		return nil, errors.New("[Wallet], Available token is not enough")
	}

	account, err := wallet.GetAddressInfo(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spenders account info failed")
	}

	txn := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types.TransferCrossChainAsset)
	txn.Payload = txPayload

	return txn, nil
}

func (wallet *WalletImpl) CreateRegisterDIDTransaction(fromAddress string, fee *Fixed64) (*types.Transaction, error) {
	// Sync chain block data before create transaction
	wallet.SyncChainData()

	redeemScript, err := contract.CreateStandardRedeemScript(wallet.GetPublicKey())
	if err != nil {
		return nil, err
	}

	c := &contract.Contract{
		Code:   redeemScript,
		Prefix: contract.PrefixCRDID,
	}

	id, _ := c.ToProgramHash().ToAddress()

	// Check if from address is valid
	spender, err := Uint168FromAddress(fromAddress)
	if err != nil {
		return nil, errors.New(fmt.Sprint("[Wallet], Invalid spender address: ", fromAddress, ", error: ", err))
	}
	// Create transaction outputs
	var totalOutputAmount = Fixed64(0) // The total amount will be spend
	var txOutputs []*types.Output      // The outputs in transaction
	totalOutputAmount += *fee          // Add transaction fee

	// Get spender's UTXOs
	UTXOs, err := wallet.GetAddressUTXOs(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spender's UTXOs failed")
	}
	availableUTXOs := wallet.removeLockedUTXOs(UTXOs) // Remove locked UTXOs
	availableUTXOs = SortUTXOs(availableUTXOs)        // Sort available UTXOs by value ASC

	// Create transaction inputs
	var txInputs []*types.Input // The inputs in transaction
	for _, utxo := range availableUTXOs {
		input := &types.Input{
			Previous: types.OutPoint{
				TxID:  utxo.Op.TxID,
				Index: utxo.Op.Index,
			},
			Sequence: utxo.LockTime,
		}
		txInputs = append(txInputs, input)
		if *utxo.Amount < totalOutputAmount {
			totalOutputAmount -= *utxo.Amount
		} else if *utxo.Amount == totalOutputAmount {
			totalOutputAmount = 0
			break
		} else if *utxo.Amount > totalOutputAmount {
			change := &types.Output{
				AssetID:     SystemAssetId,
				Value:       *utxo.Amount - totalOutputAmount,
				OutputLock:  uint32(0),
				ProgramHash: *spender,
			}
			txOutputs = append(txOutputs, change)
			totalOutputAmount = 0
			break
		}
	}
	if totalOutputAmount > 0 {
		return nil, errors.New("[Wallet], Available token is not enough")
	}

	account, err := wallet.GetAddressInfo(spender)
	if err != nil {
		return nil, errors.New("[Wallet], Get spenders account info failed")
	}

	tx := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types2.RegisterDID)
	tx.Payload = getPayloadDIDInfo(id, wallet.GetPrivateKey())

	return tx, nil
}
//23df5f7d0befb743899c22357f774df3d9ce809917b07559c59f12771e67aa31
// update operation
func getPayloadDIDInfo(id string, privateKey []byte) *types2.Operation {
	pBytes := getDIDPayloadBytes(id)
	info := new(types2.DIDPayloadInfo)
	json.Unmarshal(pBytes, info)
	p := &types2.Operation{
		Header: types2.DIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     "update",
			PreviousTxid:  "23df5f7d0befb743899c22357f774df3d9ce809917b07559c59f12771e67aa31",
		},
		Payload: base64url.EncodeToString(pBytes),
		Proof: types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "#master-key", //"did:elastos:" + id +
		},
		PayloadInfo: info,
	}

	//var payloadDidInfoData types2.PayloadDIDInfoData
	//payloadDidInfoData.Header = p.Header
	//payloadDidInfoData.Payload = p.Payload
	privateKeyHexstr := BytesToHexString(privateKey)
	fmt.Println(privateKeyHexstr)
	sign, _ := crypto.Sign(privateKey, p.GetData())
	p.Proof.Signature = base64.StdEncoding.EncodeToString(sign)
	return p
}
// create operation
//func getPayloadDIDInfo(id string, privateKey []byte) *types2.Operation {
//	pBytes := getDIDPayloadBytes(id)
//	info := new(types2.DIDPayloadInfo)
//	json.Unmarshal(pBytes, info)
//	p := &types2.Operation{
//		Header: types2.DIDHeaderInfo{
//			Specification: "elastos/did/1.0",
//			Operation:     "create",
//		},
//		Payload: base64url.EncodeToString(pBytes),
//		Proof: types2.DIDProofInfo{
//			Type:               "ECDSAsecp256r1",
//			VerificationMethod: "#master-key", //"did:elastos:" + id +
//		},
//		PayloadInfo: info,
//	}
//
//	//var payloadDidInfoData types2.PayloadDIDInfoData
//	//payloadDidInfoData.Header = p.Header
//	//payloadDidInfoData.Payload = p.Payload
//	privateKeyHexstr := BytesToHexString(privateKey)
//	fmt.Println(privateKeyHexstr)
//	sign, _ := crypto.Sign(privateKey, p.GetData())
//	p.Proof.Signature = base64.StdEncoding.EncodeToString(sign)
//	return p
//}

//rvuzuXxDeqyURvpfZ8Gy3dc6UVihC5eXcDVp9fSsdpdQ
//  21b2i2qrm18YCMpuFFYV8gPQ4jg1HwXaXCL5zQhvt58x4
// zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ
func getDIDPayloadBytes(id string) []byte {
	//return []byte(
	//	"{" +
	//		"\"id\": \"did:elastos:" + id + "\"," +
	//		"\"publicKey\": [{" +
	//		"\"id\": \"did:elastos:" + id + "\"," +
	//		"\"type\": \"ECDSAsecp256r1\"," +
	//		"\"controller\": \"did:elastos:" + id + "\"," +
	//		"\"publicKeyBase58\": \"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC\"" +
	//		"}]," +
	//		"\"authentication\": [" +
	//		"\"did:elastos:" + id + "\"" +
	//		"]," +
	//		"\"authorization\": [" +
	//		"\"did:elastos:" + id + "\"" +
	//		"]," +
	//		"\"expires\": \"2020-08-15T17:00:00Z\"" +
	//		"}",
	//)

	return []byte(
		"{" +
			"\"id\": \"did:elastos:" + id + "\"," +
			"\"publicKey\": [{" +
			"\"id\": \"did:elastos:" + id + "#master-key" + "\"," +
			"\"type\": \"ECDSAsecp256r1\"," +
			"\"controller\": \"did:elastos:" + id + "\"," +
			"\"publicKeyBase58\": \"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC\"" +
			"}]," +
			"\"authorization\": [" +
			"\"did:elastos:" + id + "\"" +
			"]," +
			"\"expires\": \"2020-08-15T17:00:00Z\"" +
			"}",
	)
}

func (wallet *WalletImpl) Sign(name string, password []byte, txn *types.Transaction) (*types.Transaction, error) {
	// Verify password
	err := wallet.Open(name, password)
	if err != nil {
		return nil, err
	}
	// Get sign type
	signType, err := crypto.GetScriptType(txn.Programs[0].Code)
	if err != nil {
		return nil, err
	}
	// Look up transaction type
	if signType == STANDARD {

		// Sign single transaction
		txn, err = wallet.signStandardTransaction(txn)
		if err != nil {
			return nil, err
		}

	} else if signType == MULTISIG {

		// Sign multi sign transaction
		txn, err = wallet.signMultiSignTransaction(txn)
		if err != nil {
			return nil, err
		}
	}

	return txn, nil
}

func (wallet *WalletImpl) signStandardTransaction(txn *types.Transaction) (*types.Transaction, error) {
	code := txn.Programs[0].Code
	// Get signer
	c := &contract.Contract{
		Code:   code,
		Prefix: contract.PrefixStandard,
	}

	programHash := c.ToProgramHash()
	// Check if current user is a valid signer
	if *programHash != *wallet.Keystore.GetProgramHash() {
		return nil, errors.New("[Wallet], Invalid signer")
	}
	// Sign transaction
	signedTx, err := wallet.Keystore.Sign(txn)
	if err != nil {
		return nil, err
	}
	// Add verify program for transaction
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signedTx)))
	buf.Write(signedTx)
	// Add signature
	txn.Programs[0].Parameter = buf.Bytes()

	return txn, nil
}

func (wallet *WalletImpl) signMultiSignTransaction(txn *types.Transaction) (*types.Transaction, error) {
	code := txn.Programs[0].Code
	param := txn.Programs[0].Parameter
	// Check if current user is a valid signer
	var signerIndex = -1
	programHashes, err := account.GetSigners(code)
	if err != nil {
		return nil, err
	}
	userProgramHash := wallet.Keystore.GetProgramHash()
	for i, programHash := range programHashes {
		if userProgramHash.ToCodeHash().IsEqual(*programHash) {
			signerIndex = i
			break
		}
	}
	if signerIndex == -1 {
		return nil, errors.New("[Wallet], Invalid multi sign signer")
	}
	// Sign transaction
	signature, err := wallet.Keystore.Sign(txn)
	if err != nil {
		return nil, err
	}
	// Append signature
	buf := new(bytes.Buffer)
	txn.SerializeUnsigned(buf)
	txn.Programs[0].Parameter, err = crypto.AppendSignature(signerIndex, signature, buf.Bytes(), code, param)
	if err != nil {
		return nil, err
	}

	return txn, nil
}

func (wallet *WalletImpl) Reset() error {
	return wallet.ResetDataStore()
}

func getSystemAssetId() Uint256 {
	systemToken := &types.Transaction{
		TxType:         types.RegisterAsset,
		PayloadVersion: 0,
		Payload: &types.PayloadRegisterAsset{
			Asset: types.Asset{
				Name:      "ELA",
				Precision: 0x08,
				AssetType: 0x00,
			},
			Amount:     0 * 100000000,
			Controller: Uint168{},
		},
		Attributes: []*types.Attribute{},
		Inputs:     []*types.Input{},
		Outputs:    []*types.Output{},
		Programs:   []*types.Program{},
	}
	return systemToken.Hash()
}

func (wallet *WalletImpl) removeLockedUTXOs(utxos []*UTXO) []*UTXO {
	var availableUTXOs []*UTXO
	var currentHeight = wallet.CurrentHeight(QueryHeightCode)
	for _, utxo := range utxos {
		if utxo.LockTime > 0 {
			if utxo.LockTime >= currentHeight {
				continue
			}
			utxo.LockTime = math.MaxUint32 - 1
		}
		availableUTXOs = append(availableUTXOs, utxo)
	}
	return availableUTXOs
}

func (wallet *WalletImpl) newTransaction(redeemScript []byte, inputs []*types.Input, outputs []*types.Output, txType types.TxType) *types.Transaction {
	// Create payload
	txPayload := &types.PayloadTransferAsset{}
	// Create attributes
	txAttr := types.NewAttribute(types.Nonce, []byte(strconv.FormatInt(rand.Int63(), 10)))
	attributes := make([]*types.Attribute, 0)
	attributes = append(attributes, &txAttr)
	// Create program
	var program = &types.Program{redeemScript, nil}
	// Create transaction
	return &types.Transaction{
		TxType:     txType,
		Payload:    txPayload,
		Attributes: attributes,
		Inputs:     inputs,
		Outputs:    outputs,
		Programs:   []*types.Program{program},
		LockTime:   0,
	}
}
