package main

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

type GnarkVerify struct{}

func init() {
	GnarkVerifyCallImpl = GnarkVerify{}
}

func (GnarkVerify) gnark_groth16_verify(id_param uint16, proof_param []byte, verify_key_param []byte,
	witness_param []byte) bool {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in gnark_groth16_verify", r)
		}
	}()

	id := ecc.ID(id_param)

	proof := groth16.NewProof(id)
	proof.ReadFrom(bytes.NewReader(proof_param))

	vk := groth16.NewVerifyingKey(id)
	vk.ReadFrom(bytes.NewReader(verify_key_param))

	witness, err := witness.New(id.ScalarField())
	if nil != err {
		return false
	}
	witness.ReadFrom(bytes.NewReader(witness_param))

	err = groth16.Verify(proof, vk, witness)
	if nil != err {
		return false
	} else {
		return true
	}
}

func (GnarkVerify) gnark_plonk_verify(id_param uint16, proof_param []byte, verify_key_param []byte,
	witness_param []byte) bool {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in gnark_plonk_verify", r)
		}
	}()

	id := ecc.ID(id_param)

	proof := plonk.NewProof(id)
	proof.ReadFrom(bytes.NewReader(proof_param))

	vk := plonk.NewVerifyingKey(id)
	vk.ReadFrom(bytes.NewReader(verify_key_param))

	witness, err := witness.New(id.ScalarField())
	if nil != err {
		return false
	}
	witness.ReadFrom(bytes.NewReader(witness_param))

	err = plonk.Verify(proof, vk, witness)
	if nil != err {
		return false
	} else {
		return true
	}
}
