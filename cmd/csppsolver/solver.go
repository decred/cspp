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
	Exponents    []int
	RepeatedRoot *big.Int
}

func (*Solver) RootFactors(args Args, res *Result) error {
	roots, exps, err := solver.RootFactors(args.A, args.F)
	if err != nil {
		return err
	}
	res.Roots = roots
	res.Exponents = exps
	return nil
}

type repeatedRoot interface {
	RepeatedRoot() *big.Int
}

func (*Solver) Roots(args Args, res *Result) error {
	roots, exps, err := solver.RootFactors(args.A, args.F)
	if err != nil {
		return err
	}
	for i, exp := range exps {
		if exp != 1 {
			res.RepeatedRoot = roots[i]
			return nil // error set by client package
		}
	}

	res.Roots = roots
	res.Exponents = exps
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
