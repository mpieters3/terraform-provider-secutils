// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure CryptoProvider satisfies various provider interfaces.
var _ provider.Provider = &CryptoProvider{}
var _ provider.ProviderWithFunctions = &CryptoProvider{}
var _ provider.ProviderWithEphemeralResources = &CryptoProvider{}

// CryptoProvider defines the provider implementation.
type CryptoProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// CryptoProviderModel describes the provider data model.
type CryptoProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
}

func (p *CryptoProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "crypto"
	resp.Version = p.version
}

func (p *CryptoProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description:         "Crypto Utilities Provider",
		MarkdownDescription: "Various cryptographic utilities to unencrypt, reencrypt, or switch format of cryptographic materials.",
	}
}

func (p *CryptoProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data CryptoProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	// No-op for now
}

func (p *CryptoProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *CryptoProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *CryptoProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *CryptoProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		NewUnencryptRFC1423Function,
		NewUnencryptPKCS8Function,
	}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &CryptoProvider{
			version: version,
		}
	}
}
