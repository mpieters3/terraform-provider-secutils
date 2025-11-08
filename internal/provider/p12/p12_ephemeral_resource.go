// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &P12EphemeralResource{}

func NewP12EphemeralResource() ephemeral.EphemeralResource {
	return &P12EphemeralResource{}
}

// P12EphemeralResource defines the ephemeral resource implementation.
type P12EphemeralResource struct{}

func (r *P12EphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_p12"
}

func (r *P12EphemeralResource) Schema(ctx context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "PKCS#12 (P12/PFX) as an ephemeral resource",
		Attributes: map[string]schema.Attribute{
			"entries": schema.ListNestedAttribute{
				MarkdownDescription: "List of key-certificate entries to store in the P12 file. **Note:** While the PKCS#12 format supports multiple private keys, the go-pkcs12 library used by this provider only supports one private key entry per file (library limitation). Provide at most one entry.",
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
							MarkdownDescription: "Alias for this entry (note: aliases are not used in P12 format)",
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
							MarkdownDescription: "Alias for this entry (note: aliases are not used in P12 format)",
							Optional:            true,
						},
					},
				},
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password to protect the P12 file. If empty or omitted, creates a passwordless P12 file (may have compatibility issues with some software).",
				Optional:            true,
				Sensitive:           true,
			},
			"p12": schema.StringAttribute{
				MarkdownDescription: "Base64-encoded P12 file content",
				Computed:            true,
				Sensitive:           true,
			},
			"base_p12": schema.StringAttribute{
				MarkdownDescription: "Optional base64-encoded P12 file content to use as the initial store",
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

// createP12 handles the logic for creating a P12 ephemeral resource.
func (r *P12EphemeralResource) createP12Ephemeral(ctx context.Context, data *P12Model, diagnostics *diag.Diagnostics) {
	createP12(ctx, data, diagnostics, "created ephemeral resource")
}

func (r *P12EphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data P12Model

	// Read Terraform config data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create the P12
	r.createP12Ephemeral(ctx, &data, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into ephemeral result data
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
