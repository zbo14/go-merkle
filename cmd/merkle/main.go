package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/zballs/merkle"
)

func main() {
	vals := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
		[]byte("e"),
		[]byte("f"),
		[]byte("g"),
		[]byte("h"),
	}
	hash := sha256.New()
	t := merkle.NewTree(hash)
	t.Construct(vals)
	fmt.Println(t)
	p, _ := t.ComputeProof([]byte("a"))
	if verified := t.VerifyProof(p); !verified {
		panic("Failed to verify merkle proof")
	}
}
