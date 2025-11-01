// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package jks

import (
	"bytes"
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
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &JKSDataSource{}

func NewJKSDataSource() datasource.DataSource {
	return &JKSDataSource{}
}

// JKSDataSource defines the data source implementation.
type JKSDataSource struct{}

// JKSDataSourceModel describes the data source model for reading JKS.
type JKSDataSourceModel struct {
	JKS             types.String `tfsdk:"jks"`
	Password        types.String `tfsdk:"password"`
	Entries         types.List   `tfsdk:"entries"`
	AdditionalCerts types.List   `tfsdk:"additional_certs"`
	Id              types.String `tfsdk:"id"`
}

// JKSDataSourceEntry describes an entry with a private key in the data source output.
type JKSDataSourceEntry struct {
	Alias            types.String `tfsdk:"alias"`
	PrivateKey       types.String `tfsdk:"private_key"`
	Certificate      types.String `tfsdk:"certificate"`
	CertificateChain types.List   `tfsdk:"certificate_chain"`
}

// JKSDataSourceCert describes a trusted certificate entry in the data source output.
type JKSDataSourceCert struct {
	Alias       types.String `tfsdk:"alias"`
	Certificate types.String `tfsdk:"certificate"`
}

func (d *JKSDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_jks"
}

func (d *JKSDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads a Java KeyStore (JKS) file and exposes its contents",
		Attributes: map[string]schema.Attribute{
			"jks": schema.StringAttribute{
				MarkdownDescription: "Base64-encoded JKS file content to read",
				Required:            true,
				Sensitive:           true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password to unlock the JKS file",
				Required:            true,
				Sensitive:           true,
			},
			"entries": schema.ListNestedAttribute{
				MarkdownDescription: "List of private key entries extracted from the keystore",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							MarkdownDescription: "Alias of the entry in the keystore",
							Computed:            true,
						},
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
			},
			"additional_certs": schema.ListNestedAttribute{
				MarkdownDescription: "List of trusted certificate entries extracted from the keystore",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							MarkdownDescription: "Alias of the certificate in the keystore",
							Computed:            true,
						},
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

func (d *JKSDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	// No configuration needed for this data source
}

func (d *JKSDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data JKSDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Decode base64 JKS
	jksBytes, err := base64.StdEncoding.DecodeString(data.JKS.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("JKS Decode Error", fmt.Sprintf("Unable to decode base64 JKS: %s", err))
		return
	}

	// Load the keystore
	ks := keystore.New()
	err = ks.Load(bytes.NewReader(jksBytes), []byte(data.Password.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("JKS Load Error", fmt.Sprintf("Unable to load JKS: %s", err))
		return
	}

	tflog.Debug(ctx, "Loaded JKS", map[string]any{
		"alias_count": len(ks.Aliases()),
	})

	// Extract entries
	var entries []JKSDataSourceEntry
	var additionalCerts []JKSDataSourceCert

	for _, alias := range ks.Aliases() {
		if ks.IsPrivateKeyEntry(alias) {
			// Extract private key entry
			keyCertChain, err := JKSAliasToPEM(&ks, alias, []byte(data.Password.ValueString()))
			if err != nil {
				resp.Diagnostics.AddError("Entry Extraction Error", fmt.Sprintf("Unable to extract entry for alias %s: %s", alias, err))
				return
			}

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

			entries = append(entries, JKSDataSourceEntry{
				Alias:            types.StringValue(alias),
				PrivateKey:       types.StringValue(string(privateKeyPEM)),
				Certificate:      types.StringValue(string(certificatePEM)),
				CertificateChain: certChainList,
			})

			tflog.Debug(ctx, "Extracted private key entry", map[string]any{
				"alias":       alias,
				"chain_count": len(keyCertChain.CertChain),
			})

		} else if ks.IsTrustedCertificateEntry(alias) {
			// Extract trusted certificate
			keyCertChain, err := JKSAliasToPEM(&ks, alias, []byte(data.Password.ValueString()))
			if err != nil {
				resp.Diagnostics.AddError("Certificate Extraction Error", fmt.Sprintf("Unable to extract certificate for alias %s: %s", alias, err))
				return
			}

			certificatePEM := pem.EncodeToMemory(keyCertChain.PublicKey)

			additionalCerts = append(additionalCerts, JKSDataSourceCert{
				Alias:       types.StringValue(alias),
				Certificate: types.StringValue(string(certificatePEM)),
			})

			tflog.Debug(ctx, "Extracted trusted certificate", map[string]any{
				"alias": alias,
			})
		}
	}

	// Convert entries to List
	entriesList, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"alias":             types.StringType,
			"private_key":       types.StringType,
			"certificate":       types.StringType,
			"certificate_chain": types.ListType{ElemType: types.StringType},
		},
	}, entries)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert additional_certs to List
	additionalCertsList, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"alias":       types.StringType,
			"certificate": types.StringType,
		},
	}, additionalCerts)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Entries = entriesList
	data.AdditionalCerts = additionalCertsList

	// Generate identifier based on the JKS content
	hash := sha256.Sum256(jksBytes)
	data.Id = types.StringValue(fmt.Sprintf("jks-%x", hash))

	tflog.Trace(ctx, "Read JKS data source", map[string]any{
		"entries_count":          len(entries),
		"additional_certs_count": len(additionalCerts),
	})

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
