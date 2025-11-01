// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/youmark/pkcs8"
)

var (
	_ function.Function = UnencryptPKCS8Function{}
)

func NewUnencryptPKCS8Function() function.Function {
	return UnencryptPKCS8Function{}
}

type UnencryptPKCS8Function struct{}

func (r UnencryptPKCS8Function) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "unencrypt_pkcs8"
}

func (r UnencryptPKCS8Function) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Unencrypts a pkcs8 password-encrypted PEM block.",
		MarkdownDescription: "Takes a password-encrypted pkcs8 private key pem and returns the decrypted private key.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "pem",
				MarkdownDescription: "Password-encrypted PEM private key string.",
			},
			function.StringParameter{
				Name:                "password",
				MarkdownDescription: "Password to decrypt the PEM.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r UnencryptPKCS8Function) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
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

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(password))
	if err != nil {
		resp.Error = function.NewFuncError("Failed to decrypt private key: " + err.Error())
		return
	}

	// Successfully parsed as PKCS#8, encode the decrypted key back to PKCS#8 DER
	var decryptedDER []byte
	if decryptedDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		resp.Error = function.NewFuncError("Failed to marshal private key: " + err.Error())
		return
	}

	decryptedPEM := pem.EncodeToMemory(&pem.Block{Type: strings.ReplaceAll(block.Type, "ENCRYPTED ", ""), Bytes: decryptedDER})
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(decryptedPEM)))
}
