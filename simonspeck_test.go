// Copyright 2013 Samuel Isaacson. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package simonspeck

import (
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"testing"
)

func TestRotate(t *testing.T) {
	if leftRotate16(0x0003, 15) != 0x8001 {
		t.Errorf("Bad 16-bit rotation")
	}
	if leftRotate24(0x00a0f12f, 3) != 0x007897d {
		t.Errorf("Bad 24-bit rotation")
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

// The endianness of these test vectors is backwards in the
// paper. The plaintext/ciphertext pairs are given in words; my code
// is little-endian, so the orders of the bytes in words are reversed.
// Note that the key and the data are given "in reverse" in the pseudocode.
// So, for example, "1918 1110 0908 0100" corresponds to the byte slice
// []byte{0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19}.
func convertTestData(s string) []byte {
	whitespace, _ := regexp.Compile("\\s+")
	bytes, err := hex.DecodeString(whitespace.ReplaceAllString(s, ""))
	if err != nil {
		panic(fmt.Sprintf("invalid test data %s: %s", s, err.Error()))
	}
	var n = len(bytes)
	for i := 0; i < n/2; i++ {
		bytes[i], bytes[n-i-1] = bytes[n-i-1], bytes[i]
	}
	return bytes
}

var testVectors = []testVector{
	testVector{
		"Simon32/64",
		NewSimon32(convertTestData("1918 1110 0908 0100")),
		convertTestData("6565 6877"),
		convertTestData("c69b e9bb"),
	},
	testVector{
		"Simon48/72",
		NewSimon48(convertTestData("121110 0a0908 020100")),
		convertTestData("612067 6e696c"),
		convertTestData("dae5ac 292cac"),
	},
	testVector{
		"Simon48/96",
		NewSimon48(convertTestData("1a1918 121110 0a0908 020100")),
		convertTestData("726963 20646e"),
		convertTestData("6e06a5 acf156"),
	},
	testVector{
		"Simon64/96",
		NewSimon64(convertTestData("13121110 0b0a0908 03020100")),
		convertTestData("6f722067 6e696c63"),
		convertTestData("5ca2e27f 111a8fc8"),
	},
	testVector{
		"Simon64/128",
		NewSimon64(convertTestData("1b1a1918 13121110 0b0a0908 03020100")),
		convertTestData("656b696c 20646e75"),
		convertTestData("44c8fc20 b9dfa07a"),
	},
	testVector{
		"Simon96/96",
		NewSimon96(convertTestData("0d0c0b0a0908 050403020100")),
		convertTestData("2072616c6c69 702065687420"),
		convertTestData("602807a462b4 69063d8ff082"),
	},
	testVector{
		"Simon96/144",
		NewSimon96(convertTestData("151413121110 0d0c0b0a0908 050403020100")),
		convertTestData("746168742074 73756420666f"),
		convertTestData("ecad1c6c451e 3f59c5db1ae9"),
	},
	testVector{
		"Simon128/128",
		NewSimon128(convertTestData("0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("6373656420737265 6c6c657661727420"),
		convertTestData("49681b1e1e54fe3f 65aa832af84e0bbc"),
	},
	testVector{
		"Simon128/192",
		NewSimon128(convertTestData("1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("206572656874206e 6568772065626972"),
		convertTestData("c4ac61effcdc0d4f 6c9c8d6e2597b85b"),
	},
	testVector{
		"Simon128/256",
		NewSimon128(convertTestData("1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("74206e69206d6f6f 6d69732061207369"),
		convertTestData("8d2b5579afc8a3a0 3bf72a87efe7b868"),
	},
	testVector{
		"Speck32/64",
		NewSpeck32(convertTestData("1918 1110 0908 0100")),
		convertTestData("6574 694c"),
		convertTestData("a868 42f2"),
	},
	testVector{
		"Speck48/72",
		NewSpeck48(convertTestData("121110 0a0908 020100")),
		convertTestData("20796c 6c6172"),
		convertTestData("c049a5 385adc"),
	},
	testVector{
		"Speck48/96",
		NewSpeck48(convertTestData("1a1918 121110 0a0908 020100")),
		convertTestData("6d2073 696874"),
		convertTestData("735e10 b6445d"),
	},
	testVector{
		"Speck64/96",
		NewSpeck64(convertTestData("13121110 0b0a0908 03020100")),
		convertTestData("74614620 736e6165"),
		convertTestData("9f7952ec 4175946c"),
	},
	testVector{
		"Speck64/96",
		NewSpeck64(convertTestData("1b1a1918 13121110 0b0a0908 03020100")),
		convertTestData("3b726574 7475432d"),
		convertTestData("8c6fa548 454e028b"),
	},
	testVector{
		"Speck96/96",
		NewSpeck96(convertTestData("0d0c0b0a0908 050403020100")),
		convertTestData("65776f68202c 656761737520"),
		convertTestData("9e4d09ab7178 62bdde8f79aa"),
	},
	testVector{
		"Speck96/144",
		NewSpeck96(convertTestData("151413121110 0d0c0b0a0908 050403020100")),
		convertTestData("656d6974206e 69202c726576"),
		convertTestData("2bf31072228a 7ae440252ee6"),
	},
	testVector{
		"Speck128/128",
		NewSpeck128(convertTestData("0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("6c61766975716520 7469206564616d20"),
		convertTestData("a65d985179783265 7860fedf5c570d18"),
	},
	testVector{
		"Speck128/192",
		NewSpeck128(convertTestData("1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("7261482066656968 43206f7420746e65"),
		convertTestData("1be4cf3a13135566 f9bc185de03c1886"),
	},
	testVector{
		"Speck128/256",
		NewSpeck128(convertTestData("1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
		convertTestData("65736f6874206e49 202e72656e6f6f70"),
		convertTestData("4109010405c0f53e 4eeeb48d9c188f43"),
	},
}

func TestSuppliedVectors(t *testing.T) {
	for _, testVec := range testVectors {
		output := make([]byte, len(testVec.ciphertext))
		testVec.cipher.Encrypt(output, testVec.plaintext)
		t.Logf("cipher: %s\tplaintext: %s\n", testVec.name, string(testVec.plaintext))
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
		"Simon48/96",
		"Simon64/128",
		"Simon96/144",
		"Simon128/256",
		"Speck32/64",
		"Speck48/96",
		"Speck64/128",
		"Speck96/144",
		"Speck128/256",
	}
	var ciphers = []cipher.Block{
		NewSimon32(randomSlice(8)),
		NewSimon48(randomSlice(12)),
		NewSimon64(randomSlice(16)),
		NewSimon96(randomSlice(18)),
		NewSimon128(randomSlice(32)),
		NewSpeck32(randomSlice(8)),
		NewSpeck48(randomSlice(12)),
		NewSpeck64(randomSlice(16)),
		NewSpeck96(randomSlice(18)),
		NewSpeck128(randomSlice(32)),
	}

	for j, c := range ciphers {
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
				t.Errorf("Encryption followed by decryption failed for %s.", names[j])
				break
			}
		}
		t.Logf("Encryption followed by decryption suceeded for %s.", names[j])
	}
}
