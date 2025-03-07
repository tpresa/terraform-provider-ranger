// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure RangerProvider satisfies various provider interfaces.
var _ provider.Provider = &RangerProvider{}
var _ provider.ProviderWithFunctions = &RangerProvider{}
var _ provider.ProviderWithEphemeralResources = &RangerProvider{}

// RangerProvider defines the provider implementation.
type RangerProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// RangerProviderModel describes the provider data model.
type RangerProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	Insecure types.Bool   `tfsdk:"insecure"`
}

// RangerClient is the client for interacting with the Apache Ranger API
type RangerClient struct {
	Endpoint   string
	Username   string
	Password   string
	Client     *http.Client
	AuthHeader string
}

func (p *RangerProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ranger"
	resp.Version = p.version
}

func (p *RangerProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Apache Ranger provider allows Terraform to manage Apache Ranger resources, such as policies.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The base URL of the Apache Ranger Admin REST API (e.g., `http://<ranger-host>:6080`)",
				Required:            true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "Ranger username with administrative privileges (for basic auth)",
				Required:            true,
				Sensitive:           true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password for the Ranger user, used for Basic Authentication",
				Required:            true,
				Sensitive:           true,
			},
			"insecure": schema.BoolAttribute{
				MarkdownDescription: "Boolean to disable TLS certificate verification, if using self-signed certs on the Ranger endpoint (default `false`)",
				Optional:            true,
			},
		},
	}
}

func (p *RangerProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data RangerProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Check for required configuration values
	if data.Endpoint.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("endpoint"),
			"Missing Ranger API Endpoint",
			"The provider requires the endpoint attribute to be set to the base URL of your Apache Ranger Admin REST API.",
		)
	}

	if data.Username.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Missing Ranger Username",
			"The provider requires a username with administrative privileges for authentication with Apache Ranger.",
		)
	}

	if data.Password.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Missing Ranger Password",
			"The provider requires a password for authentication with Apache Ranger.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Create HTTP client with optional TLS verification disabled
	tlsConfig := &tls.Config{}
	transport := &http.Transport{}

	if !data.Insecure.IsNull() && data.Insecure.ValueBool() {
		tlsConfig.InsecureSkipVerify = true
		transport.TLSClientConfig = tlsConfig
	}

	client := &http.Client{
		Transport: transport,
	}

	// Create Basic Auth header
	authString := fmt.Sprintf("%s:%s", data.Username.ValueString(), data.Password.ValueString())
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))
	authHeader := fmt.Sprintf("Basic %s", encodedAuth)

	// Create Ranger client
	rangerClient := &RangerClient{
		Endpoint:   strings.TrimSuffix(data.Endpoint.ValueString(), "/"),
		Username:   data.Username.ValueString(),
		Password:   data.Password.ValueString(),
		Client:     client,
		AuthHeader: authHeader,
	}

	resp.DataSourceData = rangerClient
	resp.ResourceData = rangerClient
}

func (p *RangerProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRangerPolicyResource,
	}
}

func (p *RangerProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *RangerProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewRangerPolicyDataSource,
	}
}

func (p *RangerProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &RangerProvider{
			version: version,
		}
	}
}
