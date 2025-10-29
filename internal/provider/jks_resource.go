// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mpieters3/terraform-provider-crypto/internal/crypto"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &JKSResource{}

func NewJKSResource() resource.Resource {
	return &JKSResource{}
}

// JKSResource defines the resource implementation.
type JKSResource struct{}

// KeyCertEntry describes a single private key, certificate and chain entry.
type KeyCertEntry struct {
	PrivateKey       types.String `tfsdk:"private_key"`
	Certificate      types.String `tfsdk:"certificate"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
	Alias            types.String `tfsdk:"alias"`
}

// CertEntry describes a single certificate with an optional alias.
type CertEntry struct {
	Certificate types.String `tfsdk:"certificate"`
	Alias       types.String `tfsdk:"alias"`
}

// JKSResourceModel describes the resource data model.
type JKSResourceModel struct {
	Entries         types.List   `tfsdk:"entries"`
	Password        types.String `tfsdk:"password"`
	BaseJKS         types.String `tfsdk:"base_jks"`
	AdditionalCerts types.List   `tfsdk:"additional_certs"`
	JKS             types.String `tfsdk:"jks"`
	Id              types.String `tfsdk:"id"`
}

func (r *JKSResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jks"
}

func (r *JKSResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{

		MarkdownDescription: "Java KeyStore (JKS) as a resource",

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
				Required:            true,
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

// hashString calculates a SHA-256 hash of the input string.
func hashString(input string) []byte {
	h := sha256.New()
	h.Write([]byte(input))
	return h.Sum(nil)
}

func decodePEMBlock(pemStr string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block, nil
}

// createOrUpdateJKS handles the common logic for creating and updating a JKS resource.
func (r *JKSResource) createOrUpdateJKS(ctx context.Context, data *JKSResourceModel, diagnostics diag.Diagnostics, operation string) {
	var ks keystore.KeyStore

	// If base JKS is provided, use it as the initial keystore
	if !data.BaseJKS.IsNull() {
		// Decode base64 JKS
		baseJKSBytes, err := base64.StdEncoding.DecodeString(data.BaseJKS.ValueString())
		if err != nil {
			diagnostics.AddError("Base JKS Error", fmt.Sprintf("Unable to decode base64 JKS: %s", err))
			return
		}

		// Load the base JKS
		ks = keystore.New()
		err = ks.Load(bytes.NewReader(baseJKSBytes), []byte(data.Password.ValueString()))
		if err != nil {
			diagnostics.AddError("Base JKS Error", fmt.Sprintf("Unable to load base JKS: %s", err))
			return
		}
	} else {
		// Create a new keystore if no base JKS is provided
		ks = keystore.New()
	}

	// Get entries from the model
	var entries []KeyCertEntry
	diagnostics.Append(data.Entries.ElementsAs(ctx, &entries, false)...)
	if diagnostics.HasError() {
		return
	}

	// Process each entry
	for _, entry := range entries {
		// Decode the private key
		privateKeyBlock, err := decodePEMBlock(entry.PrivateKey.ValueString())
		if err != nil {
			diagnostics.AddError("Private Key Error", fmt.Sprintf("Unable to decode private key: %s", err))
			return
		}

		// Decode the certificate
		certificateBlock, err := decodePEMBlock(entry.Certificate.ValueString())
		if err != nil {
			diagnostics.AddError("Certificate Error", fmt.Sprintf("Unable to decode certificate: %s", err))
			return
		}

		// Decode the certificate chain
		var certChain []types.String
		diagnostics.Append(entry.CertificateChain.ElementsAs(ctx, &certChain, false)...)
		if diagnostics.HasError() {
			return
		}

		var certChainBlocks []*pem.Block
		for _, certStr := range certChain {
			block, err := decodePEMBlock(certStr.ValueString())
			if err != nil {
				diagnostics.AddError("Certificate Chain Error", fmt.Sprintf("Unable to decode certificate chain: %s", err))
				return
			}
			certChainBlocks = append(certChainBlocks, block)
		}

		// Create KeyCertChain
		keyCertChain := &crypto.KeyCertChain{
			PrivateKey: privateKeyBlock,
			PublicKey:  certificateBlock,
			CertChain:  certChainBlocks,
		}

		// Add to JKS
		err = crypto.AddPEMToJKS(keyCertChain, &ks, []byte(data.Password.ValueString()), entry.Alias.ValueString())
		if err != nil {
			diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to create JKS: %s", err))
			return
		}
	}

	// Get entries for additional ca's to add
	var additionalCerts []CertEntry
	diagnostics.Append(data.AdditionalCerts.ElementsAs(ctx, &additionalCerts, false)...)
	if diagnostics.HasError() {
		return
	}

	// Process each entry
	for _, entry := range additionalCerts {
		block, err := decodePEMBlock(entry.Certificate.ValueString())
		if err != nil {
			diagnostics.AddError("Additional Certificate Error", fmt.Sprintf("Unable to decode additional certificate: %s", err))
			return
		}

		// Create KeyCertChain
		keyCertChain := &crypto.KeyCertChain{
			PublicKey: block,
		}

		// Add to JKS
		err = crypto.AddPEMToJKS(keyCertChain, &ks, []byte(data.Password.ValueString()), entry.Alias.ValueString())
		if err != nil {
			diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to add to JKS: %s", err))
			return
		}
	}

	// Store JKS in memory buffer
	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(data.Password.ValueString())); err != nil {
		diagnostics.AddError("JKS Error", fmt.Sprintf("Unable to store JKS: %s", err))
		return
	}

	// Encode JKS as base64
	jksBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	data.JKS = types.StringValue(jksBase64)

	// Generate/Update identifier based on the content
	data.Id = types.StringValue(fmt.Sprintf("jks-%x", hashString(jksBase64)))

	// Write logs using the tflog package
	tflog.Trace(ctx, operation+" a JKS resource")
}

func (r *JKSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data JKSResourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Handle creation
	r.createOrUpdateJKS(ctx, &data, resp.Diagnostics, "create")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JKSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data JKSResourceModel

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
	var data JKSResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Just regenerate the JKS if there's a change
	r.createOrUpdateJKS(ctx, &data, resp.Diagnostics, "update")

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *JKSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data JKSResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// No actual cleanup needed as we don't persist anything externally
}
