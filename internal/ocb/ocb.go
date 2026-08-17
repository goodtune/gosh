// Package ocb implements OCB3 authenticated encryption (RFC 7253) with
// AES-128 and a 128-bit tag, the AEAD used by the mosh datagram layer.
//
// The implementation is deliberately pure Go (crypto/aes + byte ops) so the
// binary stays CGO_ENABLED=0 and cross-compiles everywhere. Only the subset
// mosh needs is provided: 96-bit nonces, 16-byte tags, no associated data.
package ocb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"math/bits"
)

const (
	// TagLen is the authentication tag length in bytes (mosh uses 16).
	TagLen = 16
	// NonceLen is the nonce length in bytes (mosh uses 12).
	NonceLen = 12

	blockSize = 16
)

// ErrOpen is returned when authentication fails on Open. It is deliberately
// content-free: a forged and a corrupted datagram must be indistinguishable.
var ErrOpen = errors.New("ocb: message authentication failed")

// Cipher is an OCB3 AEAD instance bound to one AES-128 key.
type Cipher struct {
	block cipher.Block
	// lStar = E_K(0^128), lDollar = double(lStar), l[i] = double^{i+1}(lDollar)
	lStar   [blockSize]byte
	lDollar [blockSize]byte
	l       [][blockSize]byte
}

// New creates an OCB3-AES128 cipher. The key must be 16 bytes.
func New(key []byte) (*Cipher, error) {
	if len(key) != 16 {
		return nil, errors.New("ocb: key must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := &Cipher{block: block}
	block.Encrypt(c.lStar[:], c.lStar[:])
	double(&c.lDollar, &c.lStar)
	// Precompute L_0..L_31: enough for any datagram (2^31+ blocks would be
	// needed to exhaust it, far beyond the mosh MTU).
	c.l = make([][blockSize]byte, 32)
	double(&c.l[0], &c.lDollar)
	for i := 1; i < len(c.l); i++ {
		double(&c.l[i], &c.l[i-1])
	}
	return c, nil
}

// double is multiplication by x in GF(2^128) with the OCB polynomial.
func double(dst, src *[blockSize]byte) {
	var carry byte
	for i := blockSize - 1; i >= 0; i-- {
		b := src[i]
		dst[i] = b<<1 | carry
		carry = b >> 7
	}
	// If the shifted-out bit was set, reduce by x^128 + x^7 + x^2 + x + 1.
	dst[blockSize-1] ^= carry * 0x87
}

func xorBlock(dst, a, b *[blockSize]byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// initialOffset computes Offset_0 from the nonce (RFC 7253 section 4.2).
func (c *Cipher) initialOffset(nonce []byte) [blockSize]byte {
	// Nonce = num2str(TAGLEN mod 128, 7) || zeros(120-bitlen(N)) || 1 || N.
	// TAGLEN = 128 so the leading 7 bits are zero.
	var n [blockSize]byte
	n[blockSize-1-len(nonce)] = 0x01
	copy(n[blockSize-len(nonce):], nonce)

	bottom := int(n[blockSize-1] & 0x3F)
	n[blockSize-1] &^= 0x3F

	var ktop [blockSize]byte
	c.block.Encrypt(ktop[:], n[:])

	// Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]) — bytes 0..7 ^ 1..8.
	var stretch [blockSize + 8]byte
	copy(stretch[:], ktop[:])
	for i := 0; i < 8; i++ {
		stretch[blockSize+i] = ktop[i] ^ ktop[i+1]
	}

	// Offset_0 = Stretch[1+bottom..128+bottom] (bit indexing).
	var offset [blockSize]byte
	byteOff, bitOff := bottom/8, bottom%8
	if bitOff == 0 {
		copy(offset[:], stretch[byteOff:byteOff+blockSize])
	} else {
		for i := 0; i < blockSize; i++ {
			offset[i] = stretch[byteOff+i]<<bitOff | stretch[byteOff+i+1]>>(8-bitOff)
		}
	}
	return offset
}

// Seal encrypts and authenticates plaintext with the given 12-byte nonce and
// returns ciphertext||tag appended to dst. No associated data (mosh uses none).
func (c *Cipher) Seal(dst, nonce, plaintext []byte) ([]byte, error) {
	if len(nonce) != NonceLen {
		return nil, errors.New("ocb: nonce must be 12 bytes")
	}
	offset := c.initialOffset(nonce)
	var checksum [blockSize]byte

	out := make([]byte, len(plaintext)+TagLen)
	full := len(plaintext) / blockSize

	var tmp [blockSize]byte
	for i := 0; i < full; i++ {
		p := plaintext[i*blockSize : (i+1)*blockSize]
		xorBlock(&offset, &offset, &c.l[bits.TrailingZeros(uint(i+1))])
		for j := range tmp {
			tmp[j] = p[j] ^ offset[j]
		}
		c.block.Encrypt(tmp[:], tmp[:])
		for j := range tmp {
			out[i*blockSize+j] = tmp[j] ^ offset[j]
			checksum[j] ^= p[j]
		}
	}

	rest := plaintext[full*blockSize:]
	if len(rest) > 0 {
		xorBlock(&offset, &offset, &c.lStar)
		var pad [blockSize]byte
		c.block.Encrypt(pad[:], offset[:])
		for j, b := range rest {
			out[full*blockSize+j] = b ^ pad[j]
			checksum[j] ^= b
		}
		checksum[len(rest)] ^= 0x80
	}

	// Tag = E_K(Checksum xor Offset xor L_$); HASH(K, empty AD) = 0.
	xorBlock(&tmp, &checksum, &offset)
	xorBlock(&tmp, &tmp, &c.lDollar)
	c.block.Encrypt(tmp[:], tmp[:])
	copy(out[len(plaintext):], tmp[:])

	return append(dst, out...), nil
}

// Open authenticates and decrypts ciphertext||tag produced by Seal, appending
// the plaintext to dst. Returns ErrOpen on any authentication failure.
func (c *Cipher) Open(dst, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != NonceLen {
		return nil, errors.New("ocb: nonce must be 12 bytes")
	}
	if len(ciphertext) < TagLen {
		return nil, ErrOpen
	}
	body := ciphertext[:len(ciphertext)-TagLen]
	tag := ciphertext[len(ciphertext)-TagLen:]

	offset := c.initialOffset(nonce)
	var checksum [blockSize]byte

	out := make([]byte, len(body))
	full := len(body) / blockSize

	var tmp [blockSize]byte
	for i := 0; i < full; i++ {
		ct := body[i*blockSize : (i+1)*blockSize]
		xorBlock(&offset, &offset, &c.l[bits.TrailingZeros(uint(i+1))])
		for j := range tmp {
			tmp[j] = ct[j] ^ offset[j]
		}
		c.block.Decrypt(tmp[:], tmp[:])
		for j := range tmp {
			p := tmp[j] ^ offset[j]
			out[i*blockSize+j] = p
			checksum[j] ^= p
		}
	}

	rest := body[full*blockSize:]
	if len(rest) > 0 {
		xorBlock(&offset, &offset, &c.lStar)
		var pad [blockSize]byte
		c.block.Encrypt(pad[:], offset[:])
		for j, b := range rest {
			p := b ^ pad[j]
			out[full*blockSize+j] = p
			checksum[j] ^= p
		}
		checksum[len(rest)] ^= 0x80
	}

	xorBlock(&tmp, &checksum, &offset)
	xorBlock(&tmp, &tmp, &c.lDollar)
	c.block.Encrypt(tmp[:], tmp[:])

	if subtle.ConstantTimeCompare(tmp[:], tag) != 1 {
		return nil, ErrOpen
	}
	return append(dst, out...), nil
}
