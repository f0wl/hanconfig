// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └──────────────────────────────────┘

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ioReader is used to open the malware sample for parsing with debug/pe
func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// rc4decrypt decrypts the configuration data with the extracted key
func rc4decrypt(extkey []byte, data []byte) []byte {
	// create a new RC4 Enc/Dec Routine and pass the key
	cipher, ciphErr := rc4.NewCipher(extkey)
	check(ciphErr)
	// decrypt the config
	cipher.XORKeyStream(data, data)
	return data
}

// removeEmptyStrings cleans up unnecessarily large string arrays
// Source: https://gist.github.com/johnpili/84c3064d30a9b041c87e43ba4bcb63a2
func removeEmptyStrings(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

// Flag variables for commandline arguments
var verboseFlag bool
var jsonFlag bool

// Structure to store extracted config information
type hancitorConfig struct {
	Campaign     string   `json:"campaign"`
	C2           []string `json:"c2Servers"`
	SampleSHA256 string   `json:"sampleSHA256"`
}

func main() {

	fmt.Printf("\n888                       e88'Y88                    dP,e, ,e,          \n")
	fmt.Printf("888 ee   ,\"Y88b 888 8e   d888  'Y  e88 88e  888 8e   8b \"   \"   e88 888 \n")
	fmt.Printf("888 88b \"8\" 888 888 88b C8888     d888 888b 888 88b 888888 888 d888 888 \n")
	fmt.Printf("888 888 ,ee 888 888 888  Y888  ,d Y888 888P 888 888  888   888 Y888 888 \n")
	fmt.Printf("888 888 \"88 888 888 888   \"88,d88  \"88 88\"  888 888  888   888  \"88 888 \n")
	fmt.Printf("                                                                 ,  88P \n")
	fmt.Printf("  Hancitor Configuration Extractor                               \"8\",P\" \n")
	fmt.Printf("  Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted config to a JSON file")
	flag.BoolVar(&verboseFlag, "v", false, "Verbose output")
	flag.Parse()

	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(flag.Args()[0])
	sha256sum := calcSHA256(flag.Args()[0])

	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ File size (bytes): \t", getFileInfo(flag.Args()[0]))
	fmt.Fprintln(w1, "→ Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ Sample SHA-256: \t", sha256sum)
	w1.Flush()

	// ┌──────────────────────────────────────────────────────────────────────────────┐
	// │ Parsing the PE file, extracting the RC4 encrypted config and dectypting it   │
	// └──────────────────────────────────────────────────────────────────────────────┘

	// read the PE
	sample := ioReader(flag.Args()[0])

	// parse the PE
	f, parseErr := pe.NewFile(sample)
	check(parseErr)

	// dump out the contents of the .data section
	sectionData, dumpErr := f.Section(".data").Data()
	check(dumpErr)

	// retrieve initial key
	extKey := sectionData[16:24]

	// calculate the hashsum of the initial key
	sha1sum := sha1.Sum(extKey)

	// the RC4 key is the first 5 Bytes of the SHA1 hashsum
	rc4key := sha1sum[:5]

	// decrypt the config
	plaintext := rc4decrypt(rc4key, sectionData[24:1024])

	// trim the superfluous nullbytes from the end of the decrypted config
	plaintext = bytes.Trim(plaintext, "\x00")

	//=========================================================================

	if verboseFlag {
		color.Green("\n✓ Decrypted config hexdump:\n\n")
		fmt.Print(hex.Dump(plaintext))
	}

	// Initialize a new config struct
	var cfg hancitorConfig

	// campaign identifier
	cfg.Campaign = string(bytes.Trim(plaintext[0:16], "\x00"))

	// splitting the c2 URLs by |
	cfg.C2 = removeEmptyStrings(strings.Split(string(plaintext[16:]), "|"))

	// SHA256 hash of the sample
	cfg.SampleSHA256 = sha256sum

	//=========================================================================

	// Print the extracted configuration
	fmt.Printf("\nCampaign ID: %v\n\n", cfg.Campaign)
	
	// Loop through the c2 array and print the URLs
	for i := 0; i < len(cfg.C2); i++ {
		fmt.Printf("C2 #%v: %v\n", i, cfg.C2[i])
	}
	print("\n")

	// if hanconfig is run with -j the configuration will be written to disk in a JSON file
	if jsonFlag {

		// marshalling the config struct into a JSON string
		data, _ := json.Marshal(cfg)
		jsonString := string(data)
		// strip the unicode garbage
		jsonString = strings.ReplaceAll(jsonString, `\u0000`, "")

		filename := "hancitor_config-" + md5sum + ".json"

		// write the JSON string to a file
		jsonOutput, writeErr := os.Create(filename)
		check(writeErr)
		defer f.Close()
		n3, err := jsonOutput.WriteString(jsonString)
		check(err)
		color.Green("\n✓ Wrote %d bytes to %v\n\n", n3, filename)
		jsonOutput.Sync()
	}

}
