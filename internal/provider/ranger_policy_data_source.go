// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &RangerPolicyDataSource{}

// NewRangerPolicyDataSource creates a new data source for Ranger policies.
func NewRangerPolicyDataSource() datasource.DataSource {
	return &RangerPolicyDataSource{}
}

// RangerPolicyDataSource defines the data source implementation.
type RangerPolicyDataSource struct {
	client *RangerClient
}

// RangerPolicyDataSourceModel describes the data source data model.
type RangerPolicyDataSourceModel struct {
	ID             types.String                 `tfsdk:"id"`
	Name           types.String                 `tfsdk:"name"`
	Service        types.String                 `tfsdk:"service"`
	Description    types.String                 `tfsdk:"description"`
	IsEnabled      types.Bool                   `tfsdk:"is_enabled"`
	IsAuditEnabled types.Bool                   `tfsdk:"is_audit_enabled"`
	Resources      []RangerPolicyResourcesModel `tfsdk:"resources"`
	PolicyItems    []RangerPolicyItemModel      `tfsdk:"policy_item"`
	DenyItems      []RangerPolicyItemModel      `tfsdk:"deny_item"`
	PolicyType     types.Int64                  `tfsdk:"policy_type"`
}

// Metadata returns the data source type name.
func (d *RangerPolicyDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

// Schema defines the schema for the data source.
func (d *RangerPolicyDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieve information about an existing Apache Ranger policy",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The internal ID of the policy in Apache Ranger",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the Ranger policy",
				Required:            true,
			},
			"service": schema.StringAttribute{
				MarkdownDescription: "The name of the Ranger service (repository) to which the policy applies",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A human-readable description of the policy's purpose",
				Computed:            true,
			},
			"is_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the policy is enabled",
				Computed:            true,
			},
			"is_audit_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether access audits are enabled for this policy",
				Computed:            true,
			},
			"policy_type": schema.Int64Attribute{
				MarkdownDescription: "The type of policy (0 for access policy, 1 for data-mask, 2 for row-filter)",
				Computed:            true,
			},
			"resources": schema.ListNestedAttribute{
				MarkdownDescription: "The set of data resources that the policy protects",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The resource component name (e.g., database, table, column, etc.)",
							Computed:            true,
						},
						"values": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "One or more resource values or patterns for this component",
							Computed:            true,
						},
						"is_exclude": schema.BoolAttribute{
							MarkdownDescription: "If `true`, the values represent an exclusion (policy will apply to all *except* these values)",
							Computed:            true,
						},
						"is_recursive": schema.BoolAttribute{
							MarkdownDescription: "If `true`, the policy applies to resources under the given value hierarchically",
							Computed:            true,
						},
					},
				},
			},
			"policy_item": schema.ListNestedAttribute{
				MarkdownDescription: "Allow rule entries in the policy",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"users": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Users to whom this allow rule applies",
							Computed:            true,
						},
						"groups": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "User groups to whom this allow rule applies",
							Computed:            true,
						},
						"roles": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Ranger roles to which this allow rule applies",
							Computed:            true,
						},
						"permissions": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "The list of access actions allowed",
							Computed:            true,
						},
						"delegate_admin": schema.BoolAttribute{
							MarkdownDescription: "Whether the users/groups in this rule are allowed to further delegate (grant) this permission to others",
							Computed:            true,
						},
						"conditions": schema.MapAttribute{
							ElementType:         types.ListType{ElemType: types.StringType},
							MarkdownDescription: "Additional Ranger conditions for this rule",
							Computed:            true,
						},
					},
				},
			},
			"deny_item": schema.ListNestedAttribute{
				MarkdownDescription: "Deny rule entries in the policy",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"users": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Users to whom this deny rule applies",
							Computed:            true,
						},
						"groups": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "User groups to whom this deny rule applies",
							Computed:            true,
						},
						"roles": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Ranger roles to which this deny rule applies",
							Computed:            true,
						},
						"permissions": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "The list of access actions denied",
							Computed:            true,
						},
						"delegate_admin": schema.BoolAttribute{
							MarkdownDescription: "Whether the users/groups in this rule are allowed to further delegate (grant) this permission to others",
							Computed:            true,
						},
						"conditions": schema.MapAttribute{
							ElementType:         types.ListType{ElemType: types.StringType},
							MarkdownDescription: "Additional Ranger conditions for this rule",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *RangerPolicyDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*RangerClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *RangerClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read reads the data source.
func (d *RangerPolicyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data RangerPolicyDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Log the search parameters
	tflog.Debug(ctx, "Reading Ranger policy", map[string]interface{}{
		"service": data.Service.ValueString(),
		"name":    data.Name.ValueString(),
		"id":      data.ID.ValueString(),
	})

	var policy Policy
	var diags diag.Diagnostics

	// If an ID is provided, look up policy by ID, otherwise use service and name
	if !data.ID.IsNull() {
		policy, diags = d.getPolicyByID(ctx, data.ID.ValueString())
	} else {
		policy, diags = d.getPolicyByServiceAndName(ctx, data.Service.ValueString(), data.Name.ValueString())
	}

	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert API response to data source model
	resource := &rangerPolicyResource{client: d.client}
	model, diags := resource.convertPolicyToModel(ctx, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the data source attributes from the policy model
	data.ID = model.ID
	data.Name = model.Name
	data.Service = model.Service
	data.Description = model.Description
	data.IsEnabled = model.IsEnabled
	data.IsAuditEnabled = model.IsAuditEnabled
	data.PolicyType = model.PolicyType
	data.Resources = model.Resources
	data.PolicyItems = model.PolicyItems
	data.DenyItems = model.DenyItems

	// Set the state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// getPolicyByID retrieves a Ranger policy by its ID.
func (d *RangerPolicyDataSource) getPolicyByID(ctx context.Context, id string) (Policy, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Prepare for API request
	url := fmt.Sprintf("%s/service/public/v2/api/policy/%s", d.client.Endpoint, id)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return Policy{}, diags
	}

	request.Header.Set("Authorization", d.client.AuthHeader)
	request.Header.Set("Accept", "application/json")

	// Execute the API request
	response, err := d.client.Client.Do(request)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return Policy{}, diags
	}
	defer response.Body.Close()

	// Check if the policy exists
	if response.StatusCode == http.StatusNotFound {
		diags.AddError(
			"Ranger Policy Not Found",
			fmt.Sprintf("No policy found with ID %s", id),
		)
		return Policy{}, diags
	}

	// Check for other errors
	if response.StatusCode != http.StatusOK {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return Policy{}, diags
	}

	// Decode the response
	var policy Policy
	err = json.NewDecoder(response.Body).Decode(&policy)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not decode API response: %s", err),
		)
		return Policy{}, diags
	}

	return policy, diags
}

// getPolicyByServiceAndName retrieves a Ranger policy by service and name.
func (d *RangerPolicyDataSource) getPolicyByServiceAndName(ctx context.Context, service, name string) (Policy, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Prepare for API request
	apiURL := fmt.Sprintf("%s/service/public/v2/api/service/%s/policy", d.client.Endpoint, url.PathEscape(service))
	request, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return Policy{}, diags
	}

	// Add query parameters for name search
	q := request.URL.Query()
	q.Add("policyName", name)
	request.URL.RawQuery = q.Encode()

	request.Header.Set("Authorization", d.client.AuthHeader)
	request.Header.Set("Accept", "application/json")

	// Execute the API request
	response, err := d.client.Client.Do(request)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return Policy{}, diags
	}
	defer response.Body.Close()

	// Check for errors
	if response.StatusCode != http.StatusOK {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return Policy{}, diags
	}

	// Decode the response (the API returns a list of policies)
	var policies []Policy
	err = json.NewDecoder(response.Body).Decode(&policies)
	if err != nil {
		diags.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not decode API response: %s", err),
		)
		return Policy{}, diags
	}

	// Find the policy with the matching name
	for _, policy := range policies {
		if policy.Name == name {
			return policy, diags
		}
	}

	// Policy not found
	diags.AddError(
		"Ranger Policy Not Found",
		fmt.Sprintf("No policy found with service '%s' and name '%s'", service, name),
	)
	return Policy{}, diags
}
