package wallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/elastos/Elastos.ELA/core/contract"
	"os"

	"github.com/elastos/Elastos.ELA.Client.SideChain/log"
	"github.com/elastos/Elastos.ELA.Client.SideChain/wallet"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ripemd160"
)

const (
	MinMultiSignKeys = 3
)

func importKeystore(name string, password []byte, privateKey string) error {
	var err error
	password, err = GetPassword(password, true)
	if err != nil {
		return err
	}

	key, err := common.HexStringToBytes(privateKey)
	if err != nil {
		return err
	}

	err = wallet.ImportKeystore(name, password, key)
	if err != nil {
		return err
	}

	return ShowAccountInfo(name, password)
}

func exportKeystore(name string, password []byte) error {
	var err error
	password, err = GetPassword(password, false)
	if err != nil {
		return err
	}

	privateKey, err := wallet.ExportKeystore(name, password)
	if err != nil {
		return err
	}

	fmt.Println(common.BytesToHexString(privateKey))

	return nil
}

func createWallet(name string, password []byte) error {
	var err error
	password, err = GetPassword(password, true)
	if err != nil {
		return err
	}

	_, err = wallet.Create(name, password)
	if err != nil {
		return err
	}

	return ShowAccountInfo(name, password)
}

func changePassword(name string, password []byte, wallet wallet.Wallet) error {
	// Verify old password
	oldPassword, err := GetPassword(password, false)
	if err != nil {
		return err
	}

	err = wallet.Open(name, oldPassword)
	if err != nil {
		return err
	}

	// Input new password
	fmt.Println("# INPUT NEW PASSWORD #")
	newPassword, err := GetPassword(nil, true)
	if err != nil {
		return err
	}

	if err := wallet.ChangePassword(oldPassword, newPassword); err != nil {
		return errors.New("failed to change password")
	}

	fmt.Println("password changed successful")

	return nil
}

func listBalanceInfo(wallet wallet.Wallet) error {
	wallet.SyncChainData()
	addresses, err := wallet.GetAddresses()
	if err != nil {
		log.Error("Get addresses error:", err)
		return errors.New("get wallet addresses failed")
	}

	return ShowAccounts(addresses, nil, wallet)
}

func calculateGenesisAddress(genesisBlockHash string) error {
	genesisBlockBytes, err := common.HexStringToBytes(genesisBlockHash)
	if err != nil {
		return errors.New("genesis block hash to bytes failed")
	}
	reversedGenesisBlockBytes := common.BytesReverse(genesisBlockBytes)
	reversedGenesisBlockStr := common.BytesToHexString(reversedGenesisBlockBytes)

	fmt.Println("genesis program hash:", reversedGenesisBlockStr)

	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(reversedGenesisBlockBytes)))
	buf.Write(reversedGenesisBlockBytes)
	buf.WriteByte(byte(common.CROSSCHAIN))

	sum168 := func(prefix byte, code []byte) []byte {
		hash := sha256.Sum256(code)
		md160 := ripemd160.New()
		md160.Write(hash[:])
		return md160.Sum([]byte{prefix})
	}

	genesisProgramHash, err := common.Uint168FromBytes(sum168(byte(contract.PrefixCrossChain), buf.Bytes()))
	if err != nil {
		return errors.New("genesis block bytes to program hash failed")
	}

	genesisAddress, err := genesisProgramHash.ToAddress()
	if err != nil {
		return errors.New("genesis block hash to genesis address failed")
	}
	fmt.Println("genesis address: ", genesisAddress)

	return nil
}

func walletAction(context *cli.Context) {
	if context.NumFlags() == 0 {
		cli.ShowSubcommandHelp(context)
		os.Exit(0)
	}
	name := context.String("name")
	pass := context.String("password")

	// import wallet from an exited private key
	if privateKey := context.String("import"); len(privateKey) > 0 {
		if err := importKeystore(name, []byte(pass), privateKey); err != nil {
			fmt.Println("error: import keystore failed,", err)
			cli.ShowCommandHelpAndExit(context, "import", -1)
		}
		return
	}

	// export the private key from this wallet
	if context.Bool("export") {
		if err := exportKeystore(name, []byte(pass)); err != nil {
			fmt.Println("error: export keystore failed,", err)
			cli.ShowCommandHelpAndExit(context, "export", -1)
		}
		return
	}

	// create wallet
	if context.Bool("create") {
		if err := createWallet(name, []byte(pass)); err != nil {
			fmt.Println("error: create wallet failed,", err)
			cli.ShowCommandHelpAndExit(context, "create", 1)
		}
		return
	}

	wallet, err := wallet.GetWallet()
	if err != nil {
		fmt.Println("error: open wallet failed, ", err)
		os.Exit(2)
	}

	// show account info
	if context.Bool("account") {
		if err := ShowAccountInfo(name, []byte(pass)); err != nil {
			fmt.Println("error: show account info failed,", err)
			cli.ShowCommandHelpAndExit(context, "account", 3)
		}
		return
	}

	// change password
	if context.Bool("changepassword") {
		if err := changePassword(name, []byte(pass), wallet); err != nil {
			fmt.Println("error: change password failed,", err)
			cli.ShowCommandHelpAndExit(context, "changepassword", 4)
		}
		return
	}

	// add an account
	if input := context.String("addaccount"); input != "" {
		if err := addAccount(context, wallet, input); err != nil {
			fmt.Println("error: add standard account failed,", err)
			cli.ShowCommandHelpAndExit(context, "addaccount", 5)
		}
		return
	}

	// delete account
	if address := context.String("delaccount"); address != "" {
		if err := deleteAccount(wallet, address); err != nil {
			fmt.Println("error: delete account failed,", err)
			cli.ShowCommandHelpAndExit(context, "delaccount", 5)
		}
		return
	}

	// list accounts information
	if context.Bool("list") {
		if err := listBalanceInfo(wallet); err != nil {
			fmt.Println("error: list accounts information failed,", err)
			cli.ShowCommandHelpAndExit(context, "list", 6)
		}
		return
	}

	// transaction actions
	if param := context.String("transaction"); param != "" {
		switch param {
		case "create":
			if err := createTransaction(name, []byte(pass), context, wallet); err != nil {
				fmt.Println("error:", err)
				os.Exit(701)
			}
		case "deactivate":
			if err := createDeactivateDIDTransaction(name, []byte(pass), context, wallet); err != nil {
				fmt.Println("error:", err)
				os.Exit(705)
			}
		case "customized":
			if err := createCustomizedDIDTransaction(name, []byte(pass), context, wallet); err != nil {
				fmt.Println("error:", err)
				os.Exit(706)
			}
		case "verifiableCredential":
			if err := createVerifiableCredentialTransaction(name, []byte(pass), context, wallet); err != nil {
				fmt.Println("error:", err)
				os.Exit(702)
			}
		case "sign":
			if err := signTransaction(name, []byte(pass), context, wallet); err != nil {
				fmt.Println("error:", err)
				os.Exit(707)
			}
		case "send":
			if err := sendTransaction(context); err != nil {
				fmt.Println("error:", err)
				os.Exit(703)
			}
		default:
			cli.ShowCommandHelpAndExit(context, "transaction", 700)
		}
		return
	}

	// reset wallet
	if context.Bool("reset") {
		if err := wallet.Reset(); err != nil {
			fmt.Println("error: reset wallet data store failed,", err)
			cli.ShowCommandHelpAndExit(context, "reset", 8)
		}
		fmt.Println("wallet data store was reset successfully")
		return
	}

	//calculate genesis address
	if genesisBlockHash := context.String("genesis"); genesisBlockHash != "" {
		if err := calculateGenesisAddress(genesisBlockHash); err != nil {
			fmt.Println("error:", err)
			os.Exit(704)
		}
	}
}

func NewCommand() *cli.Command {
	return &cli.Command{
		Name:        "wallet",
		Usage:       "wallet operations",
		Description: "With side-cli wallet, you can create an account, check account balance or build, sign and send transactions.",
		ArgsUsage:   "[args]",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "password, p",
				Usage: "arguments to pass the password value",
			},
			cli.StringFlag{
				Name:  "name, n",
				Usage: "to specify the created keystore file name or the keystore file path to open",
				Value: wallet.DefaultKeystoreFile,
			},
			cli.StringFlag{
				Name:  "import",
				Usage: "create your wallet using an existed private key",
			},
			cli.BoolFlag{
				Name:  "export",
				Usage: "export your private key from this wallet",
			},
			cli.BoolFlag{
				Name:  "create, c",
				Usage: "create wallet, this will generate a keystore file within you account information",
			},
			cli.BoolFlag{
				Name:  "account, a",
				Usage: "show account address, public key and program hash",
			},
			cli.BoolFlag{
				Name:  "changepassword",
				Usage: "change the password to access this wallet, must do not forget it",
			},
			cli.BoolFlag{
				Name:  "reset",
				Usage: "clear the UTXOs stored in the local database",
			},
			cli.StringFlag{
				Name: "addaccount",
				Usage: "add a standard account with a public key, or add a multi-sign account with multiple public keys\n" +
					"\tuse -m to specify how many signatures are needed to create a valid transaction\n" +
					"\tby default M is public keys / 2 + 1, witch means greater than half",
			},
			cli.IntFlag{
				Name:  "m",
				Usage: "the M value to specify how many signatures are needed to create a valid transaction",
				Value: 0,
			},
			cli.StringFlag{
				Name:  "delaccount",
				Usage: "delete an account from database using it's address",
			},
			cli.BoolFlag{
				Name:  "list, l",
				Usage: "list accounts information, including address, public key, balance and account type.",
			},
			cli.StringFlag{
				Name: "transaction, t",
				Usage: "use [create, sign, send], to create, sign or send a transaction\n" +
					"\tcreate:\n" +
					"\t\tuse --to --amount --fee [--lock], or --file --fee [--lock]\n" +
					"\t\tto create a standard transaction, or multi output transaction\n" +
					"\tsign, send:\n" +
					"\t\tuse --file or --hex to specify the transaction file path or content\n",
			},
			cli.StringFlag{
				Name:  "from",
				Usage: "the spend address of the transaction",
			},
			cli.StringFlag{
				Name:  "to",
				Usage: "the receive address of the transaction",
			},
			cli.StringFlag{
				Name:  "amount",
				Usage: "the transfer amount of the transaction",
			},
			cli.StringFlag{
				Name:  "fee",
				Usage: "the transfer fee of the transaction",
			},
			cli.StringFlag{
				Name:  "lock",
				Usage: "the lock time to specify when the received asset can be spent",
			},
			cli.StringFlag{
				Name:  "hex",
				Usage: "the transaction content in hex string format to be sign or send",
			},
			cli.StringFlag{
				Name: "file, f",
				Usage: "the file path to specify a CSV file path with [address,amount] format as multi output content,\n" +
					"\tor the transaction file path with the hex string content to be sign or send",
			},
			cli.StringFlag{
				Name:  "key",
				Usage: "the public key of target account",
			},
			cli.StringFlag{
				Name:  "deposit",
				Usage: "create deposit transaction",
			},
			cli.StringFlag{
				Name:  "withdraw",
				Usage: "create withdraw transaction",
			},
			cli.BoolFlag{
				Name:  "registerdid",
				Usage: "create register DID transaction",
			},
			cli.StringFlag{
				Name:  "genesis, g",
				Usage: "calculate genesis address from genesis block hash",
			},
			cli.StringFlag{
				Name:  "didpubkey, dk",
				Usage: "the public key of did",
			},
			cli.StringFlag{
			Name:  "deactivedid, deactdid",
			Usage: "the deactivate did",
			},
			cli.StringFlag{
				Name:  "operation, op",
				Usage: "create or update",
			},
			cli.StringFlag{
				Name:  "pretxid, pid",
				Usage: "PreviousTxid if operation is update",
			},
			cli.StringFlag{
				Name:  "didprivatekey, dpk",
				Usage: "the private key of did",
			},
		},
		Action: walletAction,
		OnUsageError: func(c *cli.Context, err error, subCommand bool) error {
			return cli.NewExitError(err, 1)
		},
	}
}
