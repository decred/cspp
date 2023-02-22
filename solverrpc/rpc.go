package solverrpc

import (
	"io"
	"math/big"
	"net/rpc"
	"os/exec"
	"sync"
)

// SolverProcess is the process name that will be run in the background to
// handle the solving of polynomial roots.  This may be changed before calling
// Roots if the process is named differently or if an absolute path is needed.
var SolverProcess = "csppsolver"

type solverProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func (proc *solverProcess) Read(p []byte) (n int, err error) {
	return proc.stdout.Read(p)
}

func (proc *solverProcess) Write(p []byte) (n int, err error) {
	return proc.stdin.Write(p)
}

func (proc *solverProcess) Close() error {
	err := proc.stdin.Close()
	err2 := proc.stdout.Close()
	err3 := proc.cmd.Wait()
	if err == nil {
		err = err2
	}
	if err == nil {
		err = err3
	}
	return err
}

var (
	once    sync.Once
	onceErr error
	client  *rpc.Client
)

func startSolver() {
	cmd := exec.Command(SolverProcess)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		onceErr = err
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		onceErr = err
		return
	}
	err = cmd.Start()
	if err != nil {
		onceErr = err
		return
	}
	client = rpc.NewClient(&solverProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	})
}

type repeatedRoot big.Int

func (r *repeatedRoot) Error() string          { return "repeated roots" }
func (r *repeatedRoot) RepeatedRoot() *big.Int { return (*big.Int)(r) }

// Roots solves for len(a)-1 roots of the polynomial with coefficients a (mod F).
// Repeated roots are considered an error for the purposes of unique slot assignment.
func Roots(a []*big.Int, F *big.Int) ([]*big.Int, error) {
	once.Do(startSolver)
	if onceErr != nil {
		return nil, onceErr
	}

	var args struct {
		A []*big.Int
		F *big.Int
	}
	args.A = a
	args.F = F
	var result struct {
		Roots        []*big.Int
		RepeatedRoot *big.Int
	}
	err := client.Call("Solver.Roots", args, &result)
	if err != nil {
		return nil, err
	}
	if result.RepeatedRoot != nil {
		return nil, (*repeatedRoot)(result.RepeatedRoot)
	}
	return result.Roots, nil
}
