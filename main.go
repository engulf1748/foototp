package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"codeberg.org/ar324/otp"
	"github.com/atotto/clipboard"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type Config struct {
	FullyConfigured bool   `json:"fully_configured"`
	KeychainPath    string `json:"keychain_path"`
	path            string
	dir             string // `path`'s parent dir
}

type Keychain struct {
	// 'Keys'' is public and 'keys' is private. All internal operations
	// use 'keys'. 'Keys' is set before writing to the keychain, if the keychain
	// is unencrypted. The value of 'Keys' is copied over to 'keys' when
	// an unencrypted keychain is read.
	Keys map[string]otp.TOTPKey `json:"keys"`
	keys map[string]otp.TOTPKey

	Encrypted bool `json:"encrypted"`

	// If encrypted, the following three fields are non-empty hex-strings.
	EncryptedKeys string `json:"encrypted_keys"`
	Salt          string `json:"salt"`
	Nonce         string `json:"nonce"`
	// scrypt-derived encryption key.
	encryptionKey []byte

	// config has KeychainPath, which is used to write to the keychain.
	config Config
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: foototp OPTIONS COMMAND ARG
Commands:
	configure
	add ARG
	remove ARG
	generate ARG
	encrypt
	list
Options:
	-v Verbose mode (when used with 'add' or 'list').
	-c Copy generated code to clipboard (when used with 'add' or 'generate').
`) // why Stderr?
	os.Exit(2) // why 2?
}

var (
	flagVerbose = flag.Bool("v", false, "Verbose mode (when used with commands 'add' and 'list'.")
	flagClip    = flag.Bool("c", false, "Copy generated code to clipboard (when used with 'add' and 'generate').")
)

func main() {
	log.SetPrefix("foototp: ")
	log.SetFlags(0)

	flag.Usage = usage
	flag.Parse()

	config := NewConfig()
	config.read()
	// Making sure everything is 'ready' before trying to read the keychain.
	ready(config)
	keychain := NewKeychain(*config)
	keychain.read()
	if keychain.Encrypted {
		keychain.decrypt()
	}

	switch flag.Arg(0) {
	case "add":
		keychain.add(flag.Arg(1), *flagVerbose, *flagClip)
	case "encrypt":
		keychain.configureEncryption()
	case "generate":
		keychain.generate(flag.Arg(1), *flagClip)
	case "list":
		keychain.list(*flagVerbose)
	case "remove":
		keychain.remove(flag.Arg(1))
	default:
		usage()
	}
}

// Handles the 'configure' command separately. If FooTOTP is not configured,
// keychain.read() will fail. However, keychain.read() is necessary before the
// switch-case block.
func ready(config *Config) {
	if flag.Arg(0) == "configure" {
		if config.FullyConfigured && !yesOrNo("FooTOTP is already configured. Reconfigure?") {
		} else {
			config.configure()
		}
		os.Exit(0)
	} else if !config.FullyConfigured {
		log.Fatal("Please first configure FooTOTP by running 'foototp configure'.")
	}
}

// Creates and returns a new Config instance with the 'dir' and 'path'
// fields set.
func NewConfig() *Config {
	dir := filepath.Join(os.Getenv("HOME"), ".config")
	return &Config{
		dir:  dir,
		path: filepath.Join(dir, "foototp.json"),
	}
}

// Reads and unmarshals the file at c.path 'into' c. If the file does not exist,
// c is left unchanged.
func (c *Config) read() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		log.Fatal(err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		log.Fatal(err)
	}
}

// Creates and populates the config file by calling several helper functions.
func (c *Config) configure() {
	fmt.Println("Configuring FooTOTP . . .")

	c.makeDir()
	c.setKeychainPath()
	c.createKeychain()
	c.FullyConfigured = true
	c.write()

	fmt.Println("Configured FooTOTP! Run 'foototp encrypt' to encrypt your keychain.")
}

// Creates the directory that the config file resides in.
func (c *Config) makeDir() {
	err := os.MkdirAll(c.dir, 0700)
	if err != nil {
		log.Fatalf("Couldn't create config dir: %v", err)
	}
}

// Sets c.KeychainPath after obtaining the path as input from the user.
func (c *Config) setKeychainPath() {
	file := readLine("Path to 2FA keychain (will be created if it does not exist): ")
	if file == "" {
		file = "~/2fa.json"
		fmt.Printf("Path left empty. Using default %q . . .\n", file)
	}
	c.KeychainPath = expandTilde(file)
}

// Creates a file, if it does not already exist, at c.KeychainPath.  Also
// creates parent directories if required. I've included this method in Config
// because the keychain is created during configuration.
func (c *Config) createKeychain() {
	file := c.KeychainPath
	_, err := os.Stat(file)
	if err == nil {
		fmt.Printf("2FA keychain found at %q!\n", file)
		return
	}
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Printf("%q not found . . . Creating file . . .\n", file)
		d := filepath.Dir(file) // creating parent dir
		if err := os.MkdirAll(d, 0700); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("{}"), 0600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%q created . . .\n", file)
	} else {
		log.Fatal(err)
	}
}

// Writes the configuration to c.path.
func (c *Config) write() {
	data, err := json.MarshalIndent(*c, "", "\t")
	if err != nil {
		log.Fatalf("Could not marshal config: %v", err)
	}
	if err := os.WriteFile(c.path, data, 0600); err != nil {
		log.Fatal(err)
	}
}

// Prints the string argument and reads a line from the standard input. Does not
// return the trailing newline character.
func readLine(text string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(text)
	input, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Error reading input: %v", err)
	}
	return strings.Trim(input, "\n")
}

// Takes a file path and expands the initial '~/' to '$HOME/'.
func expandTilde(file string) string {
	if strings.HasPrefix(file, "~/") {
		file = strings.TrimPrefix(file, "~/")
		file = fmt.Sprintf("%s/%s", os.Getenv("HOME"), file)
	}
	return file
}

// Prints the string argument along with ' (y/n): '. Then reads user input until
// the input is either 'y' or 'n'. If 'y', true is returned. Otherwise, false is
// returned.
func yesOrNo(text string) bool {
	var resp string
	for resp != "y" && resp != "n" {
		resp = readLine(fmt.Sprintf("%s (y/n): ", text))
	}
	return resp == "y"
}

// Creates and returns a new Keychain instance with the 'config' and 'keys'
// fields set.
func NewKeychain(config Config) *Keychain {
	return &Keychain{
		config: config,
		keys:   make(map[string]otp.TOTPKey),
	}
}

// Reads and unmarshals the file at c.config.KeychainPath 'into' c. If the file
// does not exist, the program exits. Also sets c.keys.
func (c *Keychain) read() {
	if !c.config.FullyConfigured {
		log.Fatal("Not fully configured. Exiting . . .")
	}
	file := c.config.KeychainPath
	data, err := os.ReadFile(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Fatalf("Keychain doesn't exist at %q. Please reconfigure FooTOTP.", file)
		}
		log.Fatal(err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		log.Fatal(err)
	}
	if c.Keys != nil {
		c.keys = c.Keys
	}
}

// Obtains the password as input from the user, derives the encryption key by
// calling deriveEncKey, and decrypts c.EncryptedKeys. Then unmarshals the
// decrypted bytes into c.keys.
func (c *Keychain) decrypt() {
	p := getEcholessInput("Unlock the keychain (no echo): ")
	c.deriveEncKey(p)

	ek, err := hex.DecodeString(c.EncryptedKeys)
	if err != nil {
		log.Fatal(err)
	}
	nonce, err := hex.DecodeString(c.Nonce)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		log.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	dk, err := aesGCM.Open(nil, nonce, ek, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(dk, &c.keys) // c.keys 'make'd in NewKeychain
	if err != nil {
		log.Fatal(err)
	}
}

// Used to configure the encryption status of the keychain. If used for setting
// up encryption, it derives a key from the user-provided password, generates a
// random salt, and calls c.encrypt() to encrypt the Keychain instance. It then
// calls c.write() to write to the keychain.
func (c *Keychain) configureEncryption() {
	if c.Encrypted {
		opt := yesOrNo("Your keychain is already encrypted. Update password?")
		if !opt {
			return
		}
	}

	fmt.Println("Note–Leave the password blank to disable encryption.")
	p1 := getEcholessInput("Enter the password you want to use (no echo): ")
	p2 := getEcholessInput("Confirm password: ")
	if string(p1) != string(p2) {
		fmt.Println("Passwords did not match. Exiting . . .")
		return
	}
	if string(p1) == "" {
		c.disableEncryption()
		return
	}

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
	}
	c.Salt = hex.EncodeToString(salt)

	c.deriveEncKey(p1)
	c.encrypt()
	c.write()

	fmt.Println("Encryption has been enabled on your 2FA keychain.")
}

// Sets c.encryptionKey to the encryption key derived from the password. Uses
// scrypt for key derivation.
func (c *Keychain) deriveEncKey(password []byte) {
	salt, err := hex.DecodeString(c.Salt)
	if err != nil {
		log.Fatal(err)
	}

	c.encryptionKey, err = scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
}

// Disables encryption on the keychain by setting all encryption-related fields
// to their zero values and calling c.write().
func (c *Keychain) disableEncryption() {
	c.Encrypted = false
	c.EncryptedKeys, c.Nonce, c.Salt = "", "", ""
	c.write()

	fmt.Println("Encryption disabled.")
}

// Writes the keychain to c.config.KeychainPath. Call c.encrypt() before write()
// if necessary.
func (c *Keychain) write() {
	if !c.Encrypted {
		c.Keys = c.keys
	}
	data, err := json.MarshalIndent(*c, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(c.config.KeychainPath, data, 0600); err != nil {
		log.Fatal(err)
	}
}

// Encrypts c.keys and sets c.EncryptedKeys. c.encryptionKey must have already
// been set by calling deriveEncKey.
func (c *Keychain) encrypt() {
	c.Encrypted = true

	data, err := json.Marshal(c.keys)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		log.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	c.Nonce = hex.EncodeToString(nonce)

	ek := aesGCM.Seal(nil, nonce, data, nil)
	c.EncryptedKeys = hex.EncodeToString(ek)
	c.Keys = nil
}

// Lists all key names. If verbose is true, it also lists all the key parameters
// such as secret-key and hash function.
func (c *Keychain) list(verbose bool) {
	if len(c.keys) == 0 {
		fmt.Println("Your keychain is empty.")
		return
	}
	if verbose {
		fmt.Println("name,secret_key,hash_function,digits,time_step")
		for k, v := range c.keys {
			fmt.Printf("%s,%s,%s,%d,%d\n",
				k,
				v.SecretKey,
				v.HashFunction,
				v.Digits,
				v.TimeStep,
			)
		}
		return
	}
	for k := range c.keys {
		fmt.Println(k)
	}
}

// Adds a key to the c.keys, calls c.write() to save the keychain, and also
// calls generate() on the new key.
func (c *Keychain) add(name string, verbose bool, clip bool) {
	_, ok := c.keys[name]
	if ok && !yesOrNo(fmt.Sprintf("%q already exists. Overwrite?", name)) {
		return
	}

	fmt.Printf("Adding %q\n", name)
	key := c.getKeyInput(verbose)
	if !key.Validate() {
		log.Fatalln("Validation of TOTP parameters failed.")
	}
	c.keys[name] = key
	if c.Encrypted {
		c.encrypt()
	}
	c.write()
	fmt.Println("2FA key added.")

	c.generate(name, clip)
}

// Constructs and returns an otp.TOTPKey instance from user input.
func (c *Keychain) getKeyInput(verbose bool) otp.TOTPKey {
	secret := ""
	for secret == "" {
		secret = readLine("Enter shared-secret: ")
	}
	var hf otp.HashFunction
	var d byte
	var ts uint64
	if verbose {
		hf = otp.HashFunction(readLine("Enter hash algorithm (default SHA1): "))

		fmt.Printf("Enter number of digits (default 6): ")
		fmt.Scanf("%d", &d)

		fmt.Printf("Enter time step (default 30): ")
		fmt.Scanf("%d", &ts)
	}
	if hf == "" {
		hf = otp.SHA1
	}
	if d == 0 {
		d = 6
	}
	if ts == 0 {
		ts = 30
	}
	return otp.TOTPKey{
		secret,
		hf,
		d,
		ts,
		0, // T0
	}
}

// Generates a TOTP for a given key name. If clip is true, it also pastes the
// code to the clipboard.
func (c *Keychain) generate(name string, clip bool) {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("No such key %q", name)
	}

	otp := k.OTP()

	clipMsg := ""
	if clip {
		if err := clipboard.WriteAll(otp); err == nil {
			clipMsg = "(Copied to clipboard.)"
		} else {
			clipMsg = fmt.Sprintf("(Could not copy to clipboard: %v)", err)
		}
	}

	fmt.Printf("TOTP: %s %s\n", otp, clipMsg)
}

// Removes 'name' from c.keys and calls c.write().
func (c *Keychain) remove(name string) {
	_, ok := c.keys[name]
	if !ok {
		fmt.Printf("%q does not exist in the keychain.\n", name)
		return
	}

	if !yesOrNo(fmt.Sprintf("Remove %q from keychain?", name)) {
		return
	}

	delete(c.keys, name)
	if c.Encrypted {
		c.encrypt()
	}
	c.write()
	fmt.Printf("%q removed from keychain.\n", name)
}

// Takes in user-input without any echo and returns it as a byte slice. It also
// prints context information passed via the text argument.
func getEcholessInput(text string) []byte {
	fmt.Printf(text)
	input, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println() // move to next line
	return input
}
