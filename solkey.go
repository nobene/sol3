package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"strings"
	"flag"
	"io/ioutil"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
)

func derive(key []byte, chainCode []byte, segment uint32) ([]byte, []byte) {
	// Create buffer
	buf := []byte{0}
	buf = append(buf, key...)
	buf = append(buf, big.NewInt(int64(segment)).Bytes()...)

	// Calculate HMAC hash
	h := hmac.New(sha512.New, chainCode)
	h.Write(buf)
	I := h.Sum(nil)

	// Split result
	IL := I[:32]
	IR := I[32:]

	return IL, IR
}

const Hardened uint32 = 0x80000000

func main() {
	from := flag.String("f", "", "filename to read")
	flag.Parse()
	data, _ := ioutil.ReadFile(*from)
	file := string(data)
	line := 0
	temp := strings.Split(file, "\n")
	for _, item := range temp {
	if len(item) < 2 { break }
	num := strings.Fields(item)[0]
	item = strings.Join(strings.Fields(item)[1:], " ")

//	fmt.Println("[",num,"]\t",item)

	step(num, item)
	line++
    }
}

func step(num string, mnemonic string) {
	// BIP-39
	if !bip39.IsMnemonicValid(mnemonic) {
		fmt.Println("        " + num + " :  Invalid Mnemonic !!!")
		fmt.Println()
		return
	}
	seed := pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"), 2048, 64, sha512.New)

	// BIP-32
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	sum := h.Sum(nil)

	derivedSeed := sum[:32]
	chain := sum[32:]

	// BIP-44
	// m/44'/501'/index'/0'/0'  = Default path
	path := []uint32{Hardened + uint32(44), Hardened + uint32(501), Hardened + uint32(0), Hardened + uint32(0)}
	//m/44'/501'/index'/0'  = Optional path
//	path := []uint32{Hardened + uint32(44), Hardened + uint32(501), Hardened + uint32(0)}

	for _, segment := range path {
		derivedSeed, chain = derive(derivedSeed, chain, segment)
	}

	key := ed25519.NewKeyFromSeed(derivedSeed)

	// Get Solana wallet
	wallet, err := solana.WalletFromPrivateKeyBase58(base58.Encode(key))
	if err != nil {
		panic(err)
	}

	fmt.Println("     " + num +"   Default address:   " + wallet.PublicKey().String())
}
