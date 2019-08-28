package solver

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lflint -lmpfr
#include <stdlib.h>
#include <flint/flint.h>
#include <flint/fmpz_mod_poly.h>
*/
import "C"
import (
	"errors"
	"math/big"
	"unsafe"
)

// Flint uses array-of-1 typedefs for all exposed types so they may be stack
// allocated and, by taking advantage of C array pointer decaying, passed as
// function parameters without explicitly taking the address of the variable.
// Since cgo does not perform C array pointer decaying, this code instead passes
// these parameters as &x[0].

const base = 16 // for fmpz <> big.Int string conversions

// factorExp returns fac->exp[i]
func factorExp(fac *C.fmpz_mod_poly_factor_struct, i uintptr) C.long {
	return *(*C.long)(unsafe.Pointer(uintptr(unsafe.Pointer(fac.exp)) + i*C.sizeof_long))
}

// factorPoly returns the address fac->poly + i
func factorPoly(fac *C.fmpz_mod_poly_factor_struct, i uintptr) *C.fmpz_mod_poly_struct {
	return (*C.fmpz_mod_poly_struct)(unsafe.Pointer(uintptr(unsafe.Pointer(fac.poly)) + i*C.sizeof_fmpz_mod_poly_struct))
}

type repeatedRoot big.Int

func (r *repeatedRoot) Error() string          { return "repeated roots" }
func (r *repeatedRoot) RepeatedRoot() *big.Int { return (*big.Int)(r) }

// Roots solves for len(a)-1 roots of the polynomial with coefficients a (mod F).
// Repeated roots are considered an error for the purposes of unique slot assignment.
func Roots(a []*big.Int, F *big.Int) ([]*big.Int, error) {
	if len(a) < 2 {
		return nil, errors.New("too few coefficients")
	}

	var mod C.fmpz_t
	str := F.Text(base)
	cstr := C.CString(str)
	C.fmpz_set_str(&mod[0], cstr, base)
	C.free(unsafe.Pointer(cstr))
	defer C.fmpz_clear(&mod[0])

	var poly C.fmpz_mod_poly_t
	C.fmpz_mod_poly_init2(&poly[0], &mod[0], C.long(len(a)))
	defer C.fmpz_mod_poly_clear(&poly[0])
	for i := range a {
		str := a[i].Text(base)
		cstr := C.CString(str)
		var coeff C.fmpz_t
		C.fmpz_init(&coeff[0])
		C.fmpz_set_str(&coeff[0], cstr, base)
		C.fmpz_mod_poly_set_coeff_fmpz(&poly[0], C.slong(i), &coeff[0])
		C.free(unsafe.Pointer(cstr))
		C.fmpz_clear(&coeff[0])
	}

	var factor C.fmpz_mod_poly_factor_t
	C.fmpz_mod_poly_factor_init(&factor[0])
	C.fmpz_mod_poly_factor_fit_length(&factor[0], C.slong(len(a)-1))
	defer C.fmpz_mod_poly_factor_clear(&factor[0])

	C.fmpz_mod_poly_factor(&factor[0], &poly[0])

	roots := make([]*big.Int, 0, len(a)-1)
	var m C.fmpz_t
	C.fmpz_init(&m[0])
	defer C.fmpz_clear(&m[0])
	for i := C.long(0); i < factor[0].num; i++ {
		poly := factorPoly(&factor[0], uintptr(i))
		C.fmpz_mod_poly_get_coeff_fmpz(&m[0], poly, 0)

		cstr := C.fmpz_get_str(nil, base, &m[0])
		str := C.GoString(cstr)
		C.flint_free(unsafe.Pointer(cstr))

		b, ok := new(big.Int).SetString(str, base)
		if !ok {
			return nil, errors.New("failed to read fmpz")
		}
		b.Neg(b)
		b.Mod(b, F)

		if factorExp(&factor[0], uintptr(i)) != 1 {
			return nil, (*repeatedRoot)(b)
		}
		roots = append(roots, b)
	}

	if len(roots) != len(a)-1 {
		return nil, errors.New("too few roots")
	}

	return roots, nil
}
