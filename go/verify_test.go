package main

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func TestGroth16Verify(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)

	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err)

	assignment := CubicCircuit{X: 3, Y: 35}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	publicWitness, _ := witness.Public()
	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	var p_buf bytes.Buffer
	_, err = proof.WriteTo(&p_buf)
	assert.NoError(err)

	var vk_buf bytes.Buffer
	_, err = vk.WriteTo(&vk_buf)
	assert.NoError(err)

	var w_buf bytes.Buffer
	_, err = publicWitness.WriteTo(&w_buf)
	assert.NoError(err)

	ret := GnarkVerifyCallImpl.gnark_groth16_verify(uint16(ecc.BN254), p_buf.Bytes(), vk_buf.Bytes(), w_buf.Bytes())
	assert.True(ret)
}

type Circuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	const bitSize = 4000

	output := frontend.Variable(1)
	bits := api.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		if i != 0 {
			output = api.Mul(output, output)
		}
		multiply := api.Mul(output, circuit.X)
		output = api.Select(bits[len(bits)-1-i], multiply, output)

	}

	api.AssertIsEqual(circuit.Y, output)

	return nil
}

func TestPlonkVerify(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Circuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)

	scs := ccs.(*cs.SparseR1CS)
	srs, srsLagrange, err := unsafekzg.NewSRS(scs)
	assert.NoError(err)

	var w Circuit
	w.X = 2
	w.E = 2
	w.Y = 4

	witnessFull, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	assert.NoError(err)

	witnessPublic, err := frontend.NewWitness(&w, ecc.BN254.ScalarField(), frontend.PublicOnly())
	assert.NoError(err)

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	assert.NoError(err)

	var p_buf bytes.Buffer
	_, err = proof.WriteTo(&p_buf)
	assert.NoError(err)

	var vk_buf bytes.Buffer
	_, err = vk.WriteTo(&vk_buf)
	assert.NoError(err)

	var w_buf bytes.Buffer
	_, err = witnessPublic.WriteTo(&w_buf)
	assert.NoError(err)

	ret := GnarkVerifyCallImpl.gnark_plonk_verify(uint16(ecc.BN254), p_buf.Bytes(), vk_buf.Bytes(), w_buf.Bytes())
	assert.True(ret)
}
