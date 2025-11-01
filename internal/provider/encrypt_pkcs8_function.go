// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/youmark/pkcs8"
)

var (
	_ function.Function = EncryptPKCS8Function{}
)

func NewEncryptPKCS8Function() function.Function {
	return EncryptPKCS8Function{}
}

type EncryptPKCS8Function struct{}

func (r EncryptPKCS8Function) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "encrypt_pkcs8"
}

func (r EncryptPKCS8Function) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Encrypts a private key using PKCS#8 password-based encryption.",
		MarkdownDescription: "Takes an unencrypted private key PEM and returns a password-encrypted PKCS#8 private key.",
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

func (r EncryptPKCS8Function) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
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

	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try parsing as PKCS#1 RSA key
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try parsing as EC private key
			key, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				resp.Error = function.NewFuncError("Failed to parse private key: " + err.Error())
				return
			}
		}
	}

	// Encrypt the private key using PKCS#8
	encryptedDER, err := pkcs8.MarshalPrivateKey(key, []byte(password), nil)
	if err != nil {
		resp.Error = function.NewFuncError("Failed to encrypt private key: " + err.Error())
		return
	}

	encryptedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedDER,
	})
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(encryptedPEM)))
}
