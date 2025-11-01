// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var (
	_ function.Function = EncryptRFC1423Function{}
)

func NewEncryptRFC1423Function() function.Function {
	return EncryptRFC1423Function{}
}

type EncryptRFC1423Function struct{}

func (r EncryptRFC1423Function) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "encrypt_rfc1423"
}

func (r EncryptRFC1423Function) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Encrypts a private key using RFC1423 password-based encryption.",
		MarkdownDescription: "Takes an unencrypted private key PEM and returns a password-encrypted RFC1423 private key.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "pem",
				MarkdownDescription: "Unencrypted PEM private key string.",
			},
			function.StringParameter{
				Name:                "password",
				MarkdownDescription: "Password to encrypt the PEM.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r EncryptRFC1423Function) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var pemStr, password string
	resp.Error = function.ConcatFuncErrors(
		req.Arguments.Get(ctx, &pemStr, &password),
	)
	if resp.Error != nil {
		return
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		resp.Error = function.NewFuncError("Unable to decode private key into a block")
		return
	}

	// Encrypt using RFC1423 (uses AES256-CBC)
	//nolint:staticcheck // SA1019 we're intentionally using this weak cipher on function purpose
	encryptedBlock, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		resp.Error = function.NewFuncError("Failed to encrypt private key using RFC1423: " + err.Error())
		return
	}

	encryptedPEM := pem.EncodeToMemory(encryptedBlock)
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(encryptedPEM)))
}
