// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &JKSEphemeralResource{}

func NewJKSEphemeralResource() ephemeral.EphemeralResource {
	return &JKSEphemeralResource{}
}

// JKSEphemeralResource defines the ephemeral resource implementation.
type JKSEphemeralResource struct{}

func (r *JKSEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jks"
}

func (r *JKSEphemeralResource) Schema(ctx context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Java KeyStore (JKS) as an ephemeral resource",
		Attributes: map[string]schema.Attribute{
			"entries": schema.ListNestedAttribute{
				MarkdownDescription: "List of key-certificate entries to store in the keystore",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"private_key": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded private key",
							Required:            true,
							Sensitive:           true,
						},
						"certificate": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded certificate",
							Required:            true,
						},
						"certificate_chain": schema.ListAttribute{
							MarkdownDescription: "List of PEM-encoded certificates forming the certificate chain",
							Required:            true,
							ElementType:         types.StringType,
						},
						"alias": schema.StringAttribute{
							MarkdownDescription: "Alias for this entry in the keystore",
							Optional:            true,
						},
					},
				},
			},
			"additional_certs": schema.ListNestedAttribute{
				MarkdownDescription: "List of PEM-encoded additional certificates to add for trust",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"certificate": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded certificate",
							Required:            true,
						},
						"alias": schema.StringAttribute{
							MarkdownDescription: "Alias for this entry in the keystore",
							Optional:            true,
						},
					},
				},
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password to protect the JKS file",
				Required:            true,
				Sensitive:           true,
			},
			"jks": schema.StringAttribute{
				MarkdownDescription: "Base64-encoded JKS file content",
				Computed:            true,
				Sensitive:           true,
			},
			"base_jks": schema.StringAttribute{
				MarkdownDescription: "Optional base64-encoded JKS file content to use as the initial keystore",
				Optional:            true,
				Sensitive:           true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier",
				Computed:            true,
			},
		},
	}
}

// createJKS handles the logic for creating a JKS ephemeral resource.
func (r *JKSEphemeralResource) createJKS(ctx context.Context, data *JKSModel, diagnostics *diag.Diagnostics) {
	createJKS(ctx, data, diagnostics, "created ephemeral resource")
}

func (r *JKSEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data JKSModel

	// Read Terraform config data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the JKS
	r.createJKS(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into ephemeral result data
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
