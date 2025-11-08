// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &P12Resource{}

func NewP12Resource() resource.Resource {
	return &P12Resource{}
}

// P12Resource defines the resource implementation.
type P12Resource struct{}

func (r *P12Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_p12"
}

func (r *P12Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "PKCS#12 (P12/PFX) as a resource",
		Attributes: map[string]schema.Attribute{
			"entries": schema.ListNestedAttribute{
				MarkdownDescription: "List of key-certificate entries to store in the P12 file. **Note:** While the PKCS#12 format supports multiple private keys, the go-pkcs12 library used by this provider only supports one private key entry per file (library limitation). Provide at most one entry.",
				Optional:            true,
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

func (r *P12Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// No configuration needed for this resource
}

// createOrUpdateP12 handles the common logic for creating and updating a P12 resource.
func (r *P12Resource) createOrUpdateP12(ctx context.Context, data *P12Model, diagnostics *diag.Diagnostics, operation string) {
	createP12(ctx, data, diagnostics, operation+" resource")
}

func (r *P12Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data P12Model

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Handle creation
	r.createOrUpdateP12(ctx, &data, &resp.Diagnostics, "create")

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *P12Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data P12Model

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No need to re-read anything as all data is stored in the state
	// The P12 content is deterministic based on the inputs

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *P12Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data P12Model

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Just regenerate the P12 if there's a change
	r.createOrUpdateP12(ctx, &data, &resp.Diagnostics, "update")

	if resp.Diagnostics.HasError() {
		// On error, keep the prior state
		var priorData P12Model
		resp.Diagnostics.Append(req.State.Get(ctx, &priorData)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &priorData)...)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *P12Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data P12Model

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No actual cleanup needed as we don't persist anything externally
}
