package simon

import (
	"crypto/cipher"
	"math/rand"
	"testing"
)

func TestRotate(t *testing.T) {
	if leftRotate16(0x0003, 15) != 0x8001 {
		t.Errorf("Bad rotation")
	}
}

type testLFSRVector struct {
	name         string
	binaryOutput string
	lfsr         func(uint) uint
}

var testLFSRVectors = []testLFSRVector{
	testLFSRVector{
		"ShiftU",
		"11111010001001010110000111001101111101000100101011000011100110",
		ShiftU,
	},
	testLFSRVector{
		"ShiftV",
		"10001110111110010011000010110101000111011111001001100001011010",
		ShiftV,
	},
	testLFSRVector{
		"ShiftW",
		"10000100101100111110001101110101000010010110011111000110111010",
		ShiftW,
	},
}

func TestShift(t *testing.T) {
	for _, testVec := range testLFSRVectors {
		reg := uint(1)
		for i, c := range testVec.binaryOutput {
			if reg&1 == 1 && c == '0' || reg&1 == 0 && c == '1' {
				t.Errorf("Bad output at bit %d of LFSR %s\n", i, testVec.name)
				break
			}
			reg = testVec.lfsr(reg)
		}
	}
}

type testVector struct {
	name       string
	cipher     cipher.Block
	plaintext  []byte
	ciphertext []byte
}

// The endianness of these test vectors is a bit of a mess in the
// paper. The plaintext/ciphertext pairs are given in words; my code
// is little-endian, so the orders of the bytes in words are reversed.
// Note that the key is given "in reverse" in the pseudocode.
var testVectors = []testVector{
	testVector{
		"Simon32/64",
		NewSimon32([]byte{0x18, 0x19, 0x10, 0x11, 0x08, 0x09, 0x00, 0x01}),
		[]byte{0x65, 0x65, 0x77, 0x68},
		[]byte{0x9b, 0xc6, 0xbb, 0xe9},
	},
	testVector{
		"Simon64/96",
		NewSimon64([]byte{0x10, 0x11, 0x12, 0x13, 0x08, 0x09, 0x0a, 0x0b, 0x00, 0x01, 0x02, 0x03}),
		[]byte{0x67, 0x20, 0x72, 0x6f, 0x63, 0x6c, 0x69, 0x6e},
		[]byte{0x7f, 0xe2, 0xa2, 0x5c, 0xc8, 0x8f, 0x1a, 0x11},
	},
	testVector{
		"Simon64/128",
		NewSimon64([]byte{0x18, 0x19, 0x1a, 0x1b, 0x10, 0x11, 0x12, 0x13,
			0x08, 0x09, 0x0a, 0x0b, 0x00, 0x01, 0x02, 0x03}),
		[]byte{0x6c, 0x69, 0x6b, 0x65, 0x75, 0x6e, 0x64, 0x20},
		[]byte{0x20, 0xfc, 0xc8, 0x44, 0x7a, 0xa0, 0xdf, 0xb9},
	},
}

func TestSuppliedVectors(t *testing.T) {
	for _, testVec := range testVectors {
		output := make([]byte, len(testVec.ciphertext))
		testVec.cipher.Encrypt(output, testVec.plaintext)
		for i, c := range testVec.ciphertext {
			if c != output[i] {
				t.Errorf("Bad encryption for %s; expecting 0x%02x, got 0x%02x", testVec.name, c, output[i])
			}
		}
	}
}

func randomSlice(length int) []byte {
	s := make([]byte, length)
	for i, _ := range s {
		s[i] = byte(rand.Int())
	}
	return s
}

func TestEncDec32(t *testing.T) {
	var names = []string{
		"Simon32/64",
		"Simon64/96",
		"Simon64/128",
	}
	var ciphers = []cipher.Block{
		NewSimon32(randomSlice(8)),
		NewSimon64(randomSlice(12)),
		NewSimon64(randomSlice(16)),
	}

	for _, c := range ciphers {
		iv := randomSlice(c.BlockSize())
		// We use CBC as it uses both encryption and decryption.
		enc := cipher.NewCBCEncrypter(c, iv)
		dec := cipher.NewCBCDecrypter(c, iv)
		plaintext := randomSlice(16384 * c.BlockSize())
		ciphertext := make([]byte, 16384*c.BlockSize())
		enc.CryptBlocks(ciphertext, plaintext)
		dec.CryptBlocks(ciphertext, ciphertext)
		for i, p := range plaintext {
			if p != ciphertext[i] {
				t.Errorf("Encryption followed by decryption failed for %s.", names[i])
				break
			}
		}
	}
}
