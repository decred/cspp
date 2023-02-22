package main

import (
	"math/big"
	"net/rpc"
	"os"

	"decred.org/cspp/v2/solver"
)

type stdio struct{}

func (stdio) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (stdio) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}

func (stdio) Close() error {
	err := os.Stdin.Close()
	err2 := os.Stdout.Close()
	if err == nil {
		err = err2
	}
	return err
}

type Solver struct{}

type Args struct {
	A []*big.Int
	F *big.Int
}

type Result struct {
	Roots        []*big.Int
	RepeatedRoot *big.Int
}

type repeatedRoot interface {
	RepeatedRoot() *big.Int
}

func (*Solver) Roots(args Args, res *Result) error {
	roots, err := solver.Roots(args.A, args.F)
	if rr, ok := err.(repeatedRoot); ok {
		res.RepeatedRoot = rr.RepeatedRoot()
		return nil // error set by client package
	}
	if err != nil {
		return err
	}
	res.Roots = roots
	return nil
}

func main() {
	s := rpc.NewServer()
	err := s.Register(new(Solver))
	if err != nil {
		panic(err)
	}
	s.ServeConn(stdio{})
}
