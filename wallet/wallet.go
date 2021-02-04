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
	"io/ioutil"
	"math"
	"math/rand"
	"strconv"

	"github.com/elastos/Elastos.ELA.Client.SideChain/log"

	"github.com/elastos/Elastos.ELA.SideChain/types"
	. "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/btcsuite/btcutil/base58"
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
	CreateRegisterDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,operation,preTxID string) (*types.Transaction, error)
	CreateDeactivateDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey, deactivateDID string) (*types.Transaction, error)
	CreateCustomizedDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,operation,preTxID string) (*types.Transaction, error)
	CreateVerifiableCredentialTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,operation,preTxID string) (*types.Transaction, error)
	CreateDeactivateCustomizedDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey, deactivateDID string) (*types.Transaction, error)

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

//func getDIDByPublicKey(publicKey []byte) (*Uint168, error) {
//	pk, _ := crypto.DecodePoint(publicKey)
//	redeemScript, err := contract.CreateStandardRedeemScript(pk)
//	if err != nil {
//		return nil, err
//	}
//	return getDIDHashByCode(redeemScript)
//}

//func getDIDHashByCode(code []byte) (*Uint168, error) {
//	ct1, error := contract.CreateCRDIDContractByCode(code)
//	if error != nil {
//		return nil, error
//	}
//	return ct1.ToProgramHash(), error
//}
//
//func getDIDAdress(publicKey []byte) (string, error) {
//	hash, err := getDIDByPublicKey(publicKey)
//	if err != nil {
//		return "", err
//	}
//	return hash.ToAddress()
//}

func getDID(publicKey string)string  {
	pkBytes, _ := HexStringToBytes(publicKey)
	pk, _ := crypto.DecodePoint(pkBytes)
	code, _ := contract.CreateStandardRedeemScript(pk)

	newCode := make([]byte, len(code))
	copy(newCode, code)
	didCode := append(newCode[:len(newCode)-1], 0xAD)
	ct1, _ := contract.CreateCRIDContractByCode(didCode)
	did , _ := ct1.ToProgramHash().ToAddress()
	return did

	//pkBytes, _ := HexStringToBytes(publicKey)
	//did , _ := getDIDAdress(pkBytes)
	//return did
}

func getCID(publicKey string)string  {
	pkBytes, _ := HexStringToBytes(publicKey)
	pk, _ := crypto.DecodePoint(pkBytes)
	code, _ := contract.CreateStandardRedeemScript(pk)

	newCode := make([]byte, len(code))
	copy(newCode, code)
	//didCode := append(newCode[:len(newCode)-1], 0xAD)
	ct1, _ := contract.CreateCRIDContractByCode(newCode)
	did , _ := ct1.ToProgramHash().ToAddress()
	return did

	//pkBytes, _ := HexStringToBytes(publicKey)
	//did , _ := getDIDAdress(pkBytes)
	//return did
}

func (wallet *WalletImpl) CreateVerifiableCredentialTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,
	operation,preTxID string) (*types.Transaction, error) {
	// Sync chain block data before create transaction
	wallet.SyncChainData()
	fmt.Println(" CreateVerifiableCredentialTransaction   ---------preTxID ",preTxID,"operation ", operation, "didpubkey ",didPublicKey, "didPrivateKey", didPrivateKey)

	didPubkey, _ := HexStringToBytes(didPublicKey)
	base58PubKey := base58.Encode(didPubkey)
	fmt.Println("--------base58PubKey", base58PubKey)
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
	//index := 0;
	fmt.Println("totalOutputAmount", totalOutputAmount)

	for _, utxo := range availableUTXOs {
		if *utxo.Amount <= 0 {
			continue
		}
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

	tx := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types2.VerifiableCredentialTxType)
	customizedDIDDocBytes, err := LoadJsonData("./wallet/testdata/did_verifiable_credential.json")
	if err != nil {
		fmt.Println(err)
		return nil,nil
	}
	id:= getDID(didPublicKey)
	tx.Payload = getDIDVerifiableCredentialPayload(id, operation, customizedDIDDocBytes, didPrivateKey)
	return tx, nil
}

func (wallet *WalletImpl) CreateCustomizedDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,
	operation,preTxID string) (*types.Transaction, error) {
	// Sync chain block data before create transaction
	wallet.SyncChainData()
	fmt.Println(" CreateCustomizedDIDTransaction   ---------preTxID ",preTxID,"operation ", operation, "didpubkey ",didPublicKey, "didPrivateKey", didPrivateKey)

	didPubkey, _ := HexStringToBytes(didPublicKey)
	base58PubKey := base58.Encode(didPubkey)
	fmt.Println("--------base58PubKey", base58PubKey)
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
	//index := 0;
	fmt.Println("totalOutputAmount", totalOutputAmount)

	for _, utxo := range availableUTXOs {
		if *utxo.Amount <= 0 {
			continue
		}
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

	tx := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types2.CustomizedDID)
	customizedDIDDocBytes, err := LoadJsonData("./wallet/testdata/customized_did_single_sign.json")
	if err != nil {
		fmt.Println(err)
		return nil,nil
	}
	id:= getDID(didPublicKey)
	tx.Payload = getCustomizedDIDPayloadInfo(id, operation, customizedDIDDocBytes, didPrivateKey)
	return tx, nil
}

func (wallet *WalletImpl) CreateRegisterDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,operation,preTxID string) (*types.Transaction, error) {
	// Sync chain block data before create transaction
	wallet.SyncChainData()


	fmt.Println("CreateRegisterDIDTransaction ---------utxoindex ",preTxID,"operation ", operation, "didpubkey ",didPublicKey, "didPrivateKey", didPrivateKey)
	//pubkey1 := base58.Decode(didPublicKey)
	//fmt.Println("pubkey1", BytesToHexString(pubkey1))
	//privatepubkey1 := base58.Decode(didPrivateKey)
	//fmt.Println("privatepubkey1", BytesToHexString(privatepubkey1))

	didPubkey, _ := HexStringToBytes(didPublicKey)
	base58PubKey := base58.Encode(didPubkey)

	id:= getDID(didPublicKey)
	fmt.Println("id", id)

	fmt.Println("--------base58PubKey", base58PubKey)
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
	utxoIndex,err := StringToFixed64(preTxID)
	if err != nil {
		fmt.Println("StringToFixed64 ", err)
	}

	fmt.Println("totalOutputAmount", totalOutputAmount)
	fmt.Println("utxoIndex", *utxoIndex)

	for index, utxo := range availableUTXOs {
		if *utxo.Amount <= 0 {
			continue
		}
		if index < int(*utxoIndex) {
			continue
		}
		//utxoIndex = utxoIndex +1

		fmt.Println("use utxoIndex", index)
		fmt.Println("use utxo.Amount", utxo.Amount)
		//if utxoIndex == 1{
		//	fmt.Println("utxoIndex ==1 continue", utxoIndex)
		//	continue
		//}

		//fmt.Println("----use ", utxoIndex)

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
	//didprikey , _ := HexStringToBytes(didPrivateKey)
	//if didPrivateKey == ""{
	//	didprikey = wallet.GetPrivateKey()
	//}
	id1DocByts, _ := LoadJsonData("./wallet/testdata/issuer.compact.json")
	fmt.Println("id1DocByts", string(id1DocByts))
	//getOperation

	tx.Payload = getOperation(id, operation, id1DocByts, didPrivateKey)
	fmt.Println("--------tx %+v", tx)

	//tx.Payload = getPayloadDIDInfo(didPublicKey, operation, preTxID, didprikey)

	return tx, nil
}

//fromAddress 从那个地址出钱
//fee 费用
//didPublicKey 从这个公钥生出did
//didPrivateKey did指定的私钥
//operation     操作类型 deactivate 这个可以取消了。
func (wallet *WalletImpl) CreateDeactivateDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,
	deactivateDID string) (*types.Transaction, error){
	// Sync chain block data before create transaction
	wallet.SyncChainData()


	//fmt.Println("---------preTxID ",preTxID,"operation ", operation, "didpubkey ",didPublicKey, "didPrivateKey", didPrivateKey)

	didPubkey, _ := HexStringToBytes(didPublicKey)
	base58PubKey := base58.Encode(didPubkey)
	fmt.Println("--------base58PubKey", base58PubKey)
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
	index := 0;
	fmt.Println("totalOutputAmount", totalOutputAmount)

	for _, utxo := range availableUTXOs {
		if *utxo.Amount <= 0 {
			continue
		}
		index = index +1
		fmt.Println("index", index)
		fmt.Println("utxo.Amount", utxo.Amount)


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

	tx := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types2.DeactivateDID)
	didprikey , _ := HexStringToBytes(didPrivateKey)
	if didPrivateKey == ""{
		didprikey = wallet.GetPrivateKey()
	}
	tx.Payload = getDeactivateDIDPayload(didPublicKey, deactivateDID, didprikey)

	return tx, nil
}


//23df5f7d0befb743899c22357f774df3d9ce809917b07559c59f12771e67aa31
// update operation
func getPayloadDIDInfo(didPublicKey,operation, preTxId string, privateKey []byte) *types2.Operation {
	didPubkey, _ := HexStringToBytes(didPublicKey)
	id:= getDID(didPublicKey)

	base58PubKey := base58.Encode(didPubkey)
	fmt.Println("--------base58PubKey", base58PubKey)
	fmt.Println("--------id", id)
	//KEY := "03497366f22500795df7a05b98ecd88584a837b68d553aae6f8c058f13890b8424"
	//KeyBytes , _:= HexStringToBytes(KEY)
	//base58PubKeyNEW := base58.Encode(KeyBytes)
	//fmt.Println("base58PubKeyNEW ", base58PubKeyNEW)

	pBytes := getDIDPayloadBytes(id, base58PubKey)
	//fmt.Println("getPayloadDIDInfo id----  ", id)
	info := new(types2.DIDPayloadInfo)
	json.Unmarshal(pBytes, info)
	fmt.Printf("info %+v  \n", info)

	info.PublicKey[0].PublicKeyBase58 = base58PubKey

	fmt.Printf("info %+v  \n", info)
	info2Bytes, err2 :=json.Marshal(info)
	if err2 != nil {
		fmt.Println(err2)
	}
	p := &types2.Operation{
		Header: types2.DIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     operation,
			PreviousTxid:  preTxId,
		},
		Payload: base64url.EncodeToString(info2Bytes),
		Proof: types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "#master-key", //master-key test-key
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

//fromAddress 从那个地址出钱
//fee 费用
//didPublicKey 从这个公钥生出did
//didPrivateKey did指定的私钥
//operation     操作类型 deactivate 这个可以取消了。
func (wallet *WalletImpl) CreateDeactivateCustomizedDIDTransaction(fromAddress string, fee *Fixed64, didPublicKey,didPrivateKey,
	deactivateDID string) (*types.Transaction, error){
	// Sync chain block data before create transaction
	wallet.SyncChainData()


	//fmt.Println("---------preTxID ",preTxID,"operation ", operation, "didpubkey ",didPublicKey, "didPrivateKey", didPrivateKey)

	//didPubkey, _ := HexStringToBytes(didPublicKey)
	//base58PubKey := base58.Encode(didPubkey)
	//fmt.Println("--------base58PubKey", base58PubKey)
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
	index := 0;
	fmt.Println("totalOutputAmount", totalOutputAmount)

	for _, utxo := range availableUTXOs {
		if *utxo.Amount <= 0 {
			continue
		}
		index = index +1
		fmt.Println("index", index)
		fmt.Println("utxo.Amount", utxo.Amount)


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

	tx := wallet.newTransaction(account.RedeemScript, txInputs, txOutputs, types2.DeactivateCustomizedDIDTxType)
	//didprikey , _ := HexStringToBytes(didPrivateKey)
	//if didPrivateKey == ""{
	//	didprikey = wallet.GetPrivateKey()
	//}
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	fmt.Println("deactivateDID", deactivateDID)
	fmt.Println("id1", id1)
	fmt.Println("didPrivateKey", didPrivateKey)

	tx.Payload = getDeactivateCustomizedDIDPayload(deactivateDID, id1, didPrivateKey)

	return tx, nil
}


func getOperation(id string, didOperation string, docBytes []byte, privateKeyStr string) *types2.Operation {
	//pBytes := getDIDPayloadBytes(id)
	info := new(types2.DIDPayloadInfo)
	json.Unmarshal(docBytes, info)
	p := &types2.Operation{
		Header: types2.DIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		PayloadInfo: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	fmt.Println("privateKeyStr", privateKeyStr)
	fmt.Printf("Operation %+v\n", p)
	//privateKey1, _ := common.HexStringToBytes()
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func LoadJsonData(fileName string) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return []byte{}, err
	}
	return fileData, nil

}

func getDIDVerifiableCredentialPayload(id string, didOperation string, docBytes []byte,
	privateKeyStr string) *types2.VerifiableCredentialPayload {
	fmt.Println(" ---docBytes--- ", string(docBytes))
	info := new(types2.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)

	p := &types2.VerifiableCredentialPayload{
		Header: types2.CustomizedDIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: &types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		Doc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.(*types2.DIDProofInfo).Signature = base64url.EncodeToString(sign)
	return p
}



func getCustomizedDIDPayloadInfo(id string, didOperation string, docBytes []byte,
	privateKeyStr string) *types2.CustomizedDIDOperation {
	//pBytes := getDIDPayloadBytes(id)
	info := new(types2.CustomizedDIDPayload)
	json.Unmarshal(docBytes, info)

	//todo 加上m:n 是否要加pretxid,填充Proof为多个
	p := &types2.CustomizedDIDOperation{
		Header: types2.CustomizedDIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		//Proof: &types2.DIDProofInfo{
		//	Type:               "ECDSAsecp256r1",
		//	VerificationMethod: "did:elastos:" + id + "#primary",
		//},
		Doc: info,
	}
	//privateKey1 := base58.Decode(privateKeyStr)
	//privateKey1, _ := common.HexStringToBytes()
	//sign, _ := crypto.Sign(privateKey1, p.GetData())
	//p.Proof.(*types2.DIDProofInfo).Signature = base64url.EncodeToString(sign)
	return p
}

func getDeactivateCustomizedDIDPayload(customizedDID, verifiacationDID string, privateKeyStr string) *types2.DeactivateCustomizedDIDPayload {

	p := &types2.DeactivateCustomizedDIDPayload{
		Header: types2.CustomizedDIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     "",
		},
		Payload: customizedDID,
		Proof: &types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym" + "#primary",
		},
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := crypto.Sign(privateKey1, p.GetData())
	p.Proof.(*types2.DIDProofInfo).Signature = base64url.EncodeToString(sign)

	publickey := base58.Decode("2BhWFosWHCKtBQpsPD3QZUY4NwCzavKdZEh6HfQDhciAY")
	pubkey, err := crypto.DecodePoint(publickey)
	fmt.Println(err)
	err = crypto.Verify(*pubkey, p.GetData(), sign)
	fmt.Println(err)
	return p
}



//23df5f7d0befb743899c22357f774df3d9ce809917b07559c59f12771e67aa31
// update operation
//我发个交易， 指定deactivate那个did，以及用这个did的那个public key来验签
func getDeactivateDIDPayload(didPublicKey, deactivateDID string, privateKey []byte) *types2.DeactivateDIDOptPayload {
	//didPubkey, _ := HexStringToBytes(didPublicKey)
	//id:= getDID(didPublicKey)
	//
	//base58PubKey := base58.Encode(didPubkey)
	//fmt.Println("--------base58PubKey", base58PubKey)
	//fmt.Println("--------id", id)


	//pBytes := getDIDPayloadBytes(id, base58PubKey)
	////fmt.Println("getPayloadDIDInfo id----  ", id)
	//info := new(types2.DIDPayloadInfo)
	//json.Unmarshal(pBytes, info)
	//info.PublicKey[0].PublicKeyBase58 = base58PubKey
	//fmt.Printf("info %+v  \n", info)
	//info2Bytes, err2 :=json.Marshal(info)
	//if err2 != nil {
	//	fmt.Println(err2)
	//}
	p := &types2.DeactivateDIDOptPayload{
		Header: types2.DIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     "deactivate",
			PreviousTxid:  "",  //将来这个可能要删除
		},
		Payload: deactivateDID,
		Proof: types2.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "#test-key", //"did:elastos:" + id +
		},
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
func getDIDPayloadBytes(id, base58PubKey string) []byte {
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

	//return []byte(
	//	"{" +
	//		"\"id\": \"did:elastos:" + id + "\"," +
	//		"\"publicKey\": [{" +
	//		"\"id\": \"did:elastos:" + id + "#master-key" + "\"," +
	//		"\"type\": \"ECDSAsecp256r1\"," +
	//		"\"controller\": \"did:elastos:" + id + "\"," +
	//		"\"publicKeyBase58\": \"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC\"" +
	//		"}]," +
	//		"\"authorization\": [" +
	//		"\"did:elastos:" + id + "\"" +
	//		"]," +
	//		"\"expires\": \"2020-12-18T15:00:00Z\"" +
	//		"}",
	//)

	/*
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
				"\"did:elastos:" + base58PubKey + "\"," +
				"\"did:elastos:" + id + "\"" +
				"]," +
				"\"expires\": \"2020-12-18T15:00:00Z\"" +
				"}",
		)
	*/

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
			"{" +
			"\"id\": \"did:elastos:" + id + "#test-key" + "\"," +
			"\"type\": \"ECDSAsecp256r1\"," +
			"\"controller\": \"did:elastos:" + id + "\"," +
			"\"publicKeyBase58\": \"ydfwHsD9YjurYPFQ3BdUrYQxHWVTuhiepJYYZeD83M95\"" +
			"},"+
			"\"did:elastos:" + id + "\"" +
			"]," +
			"\"expires\": \"2020-12-18T15:00:00Z\"" +
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
