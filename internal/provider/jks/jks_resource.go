// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &JKSResource{}

func NewJKSResource() resource.Resource {
	return &JKSResource{}
}

// JKSResource defines the resource implementation.
type JKSResource struct{}

func (r *JKSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jks"
}

func (r *JKSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Java KeyStore (JKS) as a resource",
		Attributes: map[string]schema.Attribute{
			"entries": schema.ListNestedAttribute{
				MarkdownDescription: "List of key-certificate entries to store in the keystore",
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

func (r *JKSResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// No configuration needed for this resource
}

// createOrUpdateJKS handles the common logic for creating and updating a JKS resource.
func (r *JKSResource) createOrUpdateJKS(ctx context.Context, data *JKSModel, diagnostics *diag.Diagnostics, operation string) {
	createJKS(ctx, data, diagnostics, operation+" resource")
}

func (r *JKSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data JKSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Handle creation
	r.createOrUpdateJKS(ctx, &data, &resp.Diagnostics, "create")

	if resp.Diagnostics.HasError() {
		return
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JKSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data JKSModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No need to re-read anything as all data is stored in the state
	// The JKS content is deterministic based on the inputs

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JKSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data JKSModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Just regenerate the JKS if there's a change
	r.createOrUpdateJKS(ctx, &data, &resp.Diagnostics, "update")

	if resp.Diagnostics.HasError() {
		// On error, keep the prior state
		var priorData JKSModel
		resp.Diagnostics.Append(req.State.Get(ctx, &priorData)...)
		resp.Diagnostics.Append(resp.State.Set(ctx, &priorData)...)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JKSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data JKSModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No actual cleanup needed as we don't persist anything externally
}
