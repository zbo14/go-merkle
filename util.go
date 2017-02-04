package merkle

import (
	"golang.org/x/crypto/ripemd160"
	"hash"
)

func NewHash() hash.Hash {
	return ripemd160.New()
}

func PowOf2(i int) bool {
	return i != 0 && (i&(i-1)) == 0
}

// Calculates log base 2 of i
// If i is not a power of 2,
// returns log of the next power of 2
func Log2(i int) int {
	j, l := i, 0
	for {
		if j >>= 1; j == 0 {
			break
		}
		l++
	}
	if PowOf2(i) {
		return l
	}
	return l + 1
}

// Panic if err
func check(err error) {
	if err != nil {
		panic(err)
	}
}
