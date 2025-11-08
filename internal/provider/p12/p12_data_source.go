// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package p12

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &P12DataSource{}

func NewP12DataSource() datasource.DataSource {
	return &P12DataSource{}
}

// P12DataSource defines the data source implementation.
type P12DataSource struct{}

// P12DataSourceModel describes the data source model for reading P12.
type P12DataSourceModel struct {
	P12             types.String `tfsdk:"p12"`
	Password        types.String `tfsdk:"password"`
	Entry           types.Object `tfsdk:"entry"`
	AdditionalCerts types.List   `tfsdk:"additional_certs"`
	Id              types.String `tfsdk:"id"`
}

// P12DataSourceEntry describes the private key entry in the data source output.
type P12DataSourceEntry struct {
	PrivateKey       types.String `tfsdk:"private_key"`
	Certificate      types.String `tfsdk:"certificate"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
}

// P12DataSourceCert describes a trusted certificate entry in the data source output.
type P12DataSourceCert struct {
	Certificate types.String `tfsdk:"certificate"`
}

func (d *P12DataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_p12"
}

func (d *P12DataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a PKCS#12 (P12/PFX) file and exposes its contents",
		Attributes: map[string]schema.Attribute{
			"p12": schema.StringAttribute{
				MarkdownDescription: "Base64-encoded P12 file content to read",
				Required:            true,
				Sensitive:           true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password to unlock the P12 file. Use empty string for passwordless P12 files.",
				Optional:            true,
				Sensitive:           true,
			},
			"entry": schema.SingleNestedAttribute{
				MarkdownDescription: "The private key entry extracted from the P12 file (if present)",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"private_key": schema.StringAttribute{
						MarkdownDescription: "PEM-encoded private key",
						Computed:            true,
						Sensitive:           true,
					},
					"certificate": schema.StringAttribute{
						MarkdownDescription: "PEM-encoded certificate",
						Computed:            true,
					},
					"certificate_chain": schema.ListAttribute{
						MarkdownDescription: "List of PEM-encoded certificates forming the certificate chain (excluding the main certificate)",
						Computed:            true,
						ElementType:         types.StringType,
					},
				},
			},
			"additional_certs": schema.ListNestedAttribute{
				MarkdownDescription: "List of additional certificate entries extracted from the P12 file",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"certificate": schema.StringAttribute{
							MarkdownDescription: "PEM-encoded certificate",
							Computed:            true,
						},
					},
				},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource identifier",
				Computed:            true,
			},
		},
	}
}

func (d *P12DataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// No configuration needed for this data source
}

func (d *P12DataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data P12DataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Decode base64 P12
	p12Bytes, err := base64.StdEncoding.DecodeString(data.P12.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("P12 Decode Error", fmt.Sprintf("Unable to decode base64 P12: %s", err))
		return
	}

	// Extract the key and certificate chain
	keyCertChain, err := P12ToPEM(p12Bytes, data.Password.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("P12 Load Error", fmt.Sprintf("Unable to load P12: %s", err))
		return
	}

	tflog.Debug(ctx, "Loaded P12", map[string]any{
		"has_private_key": keyCertChain.PrivateKey != nil,
		"has_certificate": keyCertChain.PublicKey != nil,
		"chain_count":     len(keyCertChain.CertChain),
	})

	// Process the entry if a private key is present
	if keyCertChain.PrivateKey != nil && keyCertChain.PublicKey != nil {
		// Convert to PEM strings
		privateKeyPEM := pem.EncodeToMemory(keyCertChain.PrivateKey)
		certificatePEM := pem.EncodeToMemory(keyCertChain.PublicKey)

		// Convert certificate chain to PEM strings
		var certChainPEMs []types.String
		for _, certBlock := range keyCertChain.CertChain {
			certPEM := pem.EncodeToMemory(certBlock)
			certChainPEMs = append(certChainPEMs, types.StringValue(string(certPEM)))
		}

		certChainList, diags := types.ListValueFrom(ctx, types.StringType, certChainPEMs)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		entry := P12DataSourceEntry{
			PrivateKey:       types.StringValue(string(privateKeyPEM)),
			Certificate:      types.StringValue(string(certificatePEM)),
			CertificateChain: certChainList,
		}

		entryObj, diags := types.ObjectValueFrom(ctx, map[string]attr.Type{
			"private_key":       types.StringType,
			"certificate":       types.StringType,
			"certificate_chain": types.ListType{ElemType: types.StringType},
		}, entry)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		data.Entry = entryObj

		tflog.Debug(ctx, "Extracted private key entry", map[string]any{
			"chain_count": len(keyCertChain.CertChain),
		})
	} else {
		// No private key entry, set to null
		data.Entry = types.ObjectNull(map[string]attr.Type{
			"private_key":       types.StringType,
			"certificate":       types.StringType,
			"certificate_chain": types.ListType{ElemType: types.StringType},
		})
	}

	// Process additional certificates (those not associated with the private key)
	var additionalCerts []P12DataSourceCert
	// In P12, all certificates beyond the leaf and chain are considered additional
	// For now, we'll leave this empty as the standard P12 format includes all certs in the chain
	// Convert additional_certs to List
	additionalCertsList, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"certificate": types.StringType,
		},
	}, additionalCerts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.AdditionalCerts = additionalCertsList

	// Generate identifier based on the P12 content
	hash := sha256.Sum256(p12Bytes)
	data.Id = types.StringValue(fmt.Sprintf("p12-%x", hash))

	tflog.Trace(ctx, "Read P12 data source", map[string]any{
		"has_entry":              !data.Entry.IsNull(),
		"additional_certs_count": len(additionalCerts),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
