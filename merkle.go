package merkle

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"hash"
)

type Node struct {
	h                   []byte
	parent, left, right *Node
}

func (nd *Node) IsLeaf() bool {
	return nd.right == nil && nd.left == nil
}

func (nd *Node) String() string {
	return fmt.Sprintf("NODE(%x..) ", nd.h[:3])
}

type Level []*Node

func (l Level) String() string {
	var buf bytes.Buffer
	buf.WriteString("------LEVEL------\n")
	for _, nd := range l {
		buf.WriteString(nd.String())
	}
	buf.WriteString("\n")
	return buf.String()
}

func hashing(nd *Node, hash hash.Hash) ([]byte, error) {
	n := nd
	var h []byte //specify hash size
	for {
		if n.h != nil {
			if n == nd {
				return n.h, nil
			}
			n = n.parent
			continue
		} else if n.IsLeaf() {
			return nil, errors.New("Leaf node does not have value")
		} else if n.left.h == nil {
			n = n.left
			continue
		}
		h = n.left.h
		if n.right != nil {
			if n.right.h == nil {
				n = n.right
				continue
			}
			h = append(h, n.right.h...)
		}
		hash.Reset()
		hash.Write(h)
		n.h = hash.Sum(nil)
		if n == nd {
			return n.h, nil
		}
		n = n.parent
	}
}

type Tree struct {
	hash   hash.Hash
	levels []Level
}

type Branch [][]byte

func (b Branch) String() string {
	var buf bytes.Buffer
	buf.WriteString("[BRANCH]\n")
	for _, h := range b {
		buf.WriteString(fmt.Sprintf("HASH(%x..)\n", h[:3]))
	}
	return buf.String()
}

func NewTree(hash hash.Hash) *Tree {
	return &Tree{hash: hash}
}

func (t *Tree) String() string {
	var buf bytes.Buffer
	for _, l := range t.levels {
		buf.WriteString(l.String())
	}
	return buf.String()
}

func (t *Tree) Height() int {
	return len(t.levels)
}

func (t *Tree) Empty() bool {
	return t.Height() == 0
}

func (t *Tree) root() *Node {
	return t.levels[0][0]
}

func (t *Tree) level(height int) (Level, error) {
	height--
	if height < 0 || height > t.Height() {
		return nil, errors.New("Height out of range")
	}
	return t.levels[height], nil
}

type Proof struct {
	br Branch
	h  []byte
}

func NewProof(br Branch, h []byte) *Proof {
	return &Proof{br, h}
}

func (p *Proof) String() string {
	return fmt.Sprintf("---PROOF---\n[%x..]\n\n%v", p.h[:3], p.br)
}

func (t *Tree) ComputeProof(val []byte) (*Proof, error) {
	t.hash.Reset()
	t.hash.Write(val)
	h := t.hash.Sum(nil)
	height := t.Height()
	leaves, err := t.level(height)
	if err != nil {
		return nil, err
	}
	var i int
	for i, _ = range leaves {
		if bytes.Equal(leaves[i].h, h) {
			break
		}
	}
	if i == len(leaves) {
		return nil, errors.New("Val not found")
	}
	var br Branch
	if (i^1)&1 == 0 {
		br = append(br, append([]byte{0}, leaves[i^1].h...))
	} else {
		br = append(br, append([]byte{1}, leaves[i^1].h...))
	}
	for {
		i /= 2
		height--
		level, err := t.level(height)
		if err != nil {
			return nil, err
		}
		if len(level) == 1 {
			// We hit root... break
			break
		}
		if (i^1)&1 == 0 {
			br = append(br, append([]byte{0}, level[i^1].h...))
		} else {
			br = append(br, append([]byte{1}, level[i^1].h...))
		}
	}
	proof := NewProof(br, h)
	return proof, nil
}

func (t *Tree) VerifyProof(p *Proof) bool {
	for _, h := range p.br {
		if h != nil {
			if h[0] == 0 {
				h = h[1:]
				p.h = append(h, p.h...)
			} else if h[0] == 1 {
				h = h[1:]
				p.h = append(p.h, h...)
			} else {
				// shouldn't get here
			}
		} else {
			// just hash the previous hash
			// should we ever get here?
		}
		t.hash.Reset()
		t.hash.Write(p.h)
		p.h = t.hash.Sum(nil)
	}
	root := t.root()
	match := bytes.Equal(root.h, p.h)
	return match
}

// Calculates height of tree and creates that many levels
// Then hashes vals and puts those in leaf nodes
// Establishes parent-child relationships between each level
// Sets hashes of non-leaf nodes by hashing concatenation
// of the children hashes.. finally returns the root hash

func (t *Tree) Construct(vals [][]byte) ([]byte, error) {
	if !t.Empty() {
		// Tree should be empty
		return nil, errors.New("Tree is not empty")
	} else if len(vals) == 0 {
		return nil, errors.New("No vals")
	}
	count := len(vals)
	height := calcTreeHeight(count)
	t.levels = make([]Level, height)
	height--
	t.levels[height] = make(Level, count)
	for i, val := range vals {
		// For leaf nodes, we just hash the vals
		t.hash.Reset()
		t.hash.Write(val)
		h := t.hash.Sum(nil)
		t.levels[height][i] = &Node{h: h}
	}
	for height > 0 {
		children := t.levels[height]
		height--
		t.levels[height] = constructLevel(children)
	}
	h, err := t.setHashes(t.hash)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// Set hash of each non-leaf node
// Hash the concatenation of children hashes
func (t *Tree) setHashes(hash hash.Hash) ([]byte, error) {
	root := t.root()
	return hashing(root, hash)
}

func constructLevel(children Level) Level {
	size := (len(children) + (len(children) % 2)) / 2
	parents := make(Level, size)
	for i := 0; i < size; i++ {
		nd := &Node{}
		il, ir := 2*i, 2*i+1
		nl := children[il]
		nd.left = nl
		nl.parent = nd
		if ir < len(children) {
			nr := children[ir]
			nd.right = nr
			nr.parent = nd
		}
		parents[i] = nd
	}
	return parents
}

func calcTreeHeight(count int) int {
	switch {
	case count == 0:
		return 0
	case count == 1:
		return 2
	default:
		return Log2(count) + 1
	}
}
