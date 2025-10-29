// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var (
	_ function.Function = UnencryptRFC1423Function{}
)

func NewUnencryptRFC1423Function() function.Function {
	return UnencryptRFC1423Function{}
}

type UnencryptRFC1423Function struct{}

func (r UnencryptRFC1423Function) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "unencrypt_rfc1423"
}

func (r UnencryptRFC1423Function) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary:             "Unencrypts a RFC1423 password-encrypted PEM block.",
		MarkdownDescription: "Takes a RFC1423 password-encrypted PEM and returns the decrypted RFC1423.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "der",
				MarkdownDescription: "RFC1423 password-encrypted PEM string.",
			},
			function.StringParameter{
				Name:                "password",
				MarkdownDescription: "Password to decrypt the PEM.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (r UnencryptRFC1423Function) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
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

	var decryptedDER []byte

	decryptedDER, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		resp.Error = function.NewFuncError("Unable to decode private key with password using RFC1423: " + err.Error())
		return
	}

	decryptedPEM := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: decryptedDER})
	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, string(decryptedPEM)))
}
