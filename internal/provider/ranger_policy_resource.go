// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &rangerPolicyResource{}
	_ resource.ResourceWithImportState = &rangerPolicyResource{}
)

// NewRangerPolicyResource is a helper function to simplify the provider implementation.
func NewRangerPolicyResource() resource.Resource {
	return &rangerPolicyResource{}
}

// rangerPolicyResource is the resource implementation.
type rangerPolicyResource struct {
	client *RangerClient
}

// RangerPolicyResourceModel maps the resource schema to Go objects.
type RangerPolicyResourceModel struct {
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

// RangerPolicyResourcesModel represents a resource in a Ranger policy.
type RangerPolicyResourcesModel struct {
	Type        types.String   `tfsdk:"type"`
	Values      []types.String `tfsdk:"values"`
	IsExclude   types.Bool     `tfsdk:"is_exclude"`
	IsRecursive types.Bool     `tfsdk:"is_recursive"`
}

// RangerPolicyItemModel represents the policy items in a Ranger policy (allow/deny rules).
type RangerPolicyItemModel struct {
	Users         []types.String            `tfsdk:"users"`
	Groups        []types.String            `tfsdk:"groups"`
	Roles         []types.String            `tfsdk:"roles"`
	Permissions   []types.String            `tfsdk:"permissions"`
	DelegateAdmin types.Bool                `tfsdk:"delegate_admin"`
	Conditions    map[string][]types.String `tfsdk:"conditions"`
}

// Policy represents the Apache Ranger policy JSON structure
type Policy struct {
	ID              int64                      `json:"id,omitempty"`
	Name            string                     `json:"name"`
	Service         string                     `json:"service"`
	Description     string                     `json:"description,omitempty"`
	IsEnabled       bool                       `json:"isEnabled"`
	IsAuditEnabled  bool                       `json:"isAuditEnabled"`
	Resources       map[string]PolicyResources `json:"resources"`
	PolicyItems     []PolicyItem               `json:"policyItems,omitempty"`
	DenyPolicyItems []PolicyItem               `json:"denyPolicyItems,omitempty"`
	PolicyType      int64                      `json:"policyType"`
}

// PolicyResources represents a resource in the Ranger policy JSON
type PolicyResources struct {
	Values      []string `json:"values"`
	IsExclude   bool     `json:"isExcludeSupported,omitempty"`
	IsRecursive bool     `json:"isRecursive,omitempty"`
}

// PolicyItem represents the policy items in the Ranger policy JSON
type PolicyItem struct {
	Users         []string                 `json:"users,omitempty"`
	Groups        []string                 `json:"groups,omitempty"`
	Roles         []string                 `json:"roles,omitempty"`
	Accesses      []Access                 `json:"accesses"`
	DelegateAdmin bool                     `json:"delegateAdmin"`
	Conditions    []map[string]interface{} `json:"conditions,omitempty"`
}

// Access represents a permission in the Ranger policy JSON
type Access struct {
	Type      string `json:"type"`
	IsAllowed bool   `json:"isAllowed"`
}

// Metadata returns the resource type name.
func (r *rangerPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

// Schema defines the schema for the resource.
func (r *rangerPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Apache Ranger Policy resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The internal ID of the policy in Apache Ranger",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the Ranger policy. Must be unique within the specified service",
				Required:            true,
			},
			"service": schema.StringAttribute{
				MarkdownDescription: "The name of the Ranger service (repository) to which the policy applies",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A human-readable description of the policy's purpose",
				Optional:            true,
			},
			"is_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the policy is enabled (`true` by default)",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"is_audit_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether access audits are enabled for this policy (`true` by default)",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"policy_type": schema.Int64Attribute{
				MarkdownDescription: "The type of policy (0 for access policy, 1 for data-mask, 2 for row-filter)",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(0),
			},
			"resources": schema.ListNestedAttribute{
				MarkdownDescription: "The set of data resources that the policy protects",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"type": schema.StringAttribute{
							MarkdownDescription: "The resource component name (e.g., database, table, column, etc.)",
							Required:            true,
						},
						"values": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "One or more resource values or patterns for this component",
							Required:            true,
						},
						"is_exclude": schema.BoolAttribute{
							MarkdownDescription: "If `true`, the values represent an exclusion (policy will apply to all *except* these values)",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
						},
						"is_recursive": schema.BoolAttribute{
							MarkdownDescription: "If `true`, the policy applies to resources under the given value hierarchically",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
						},
					},
				},
			},
			"policy_item": schema.ListNestedAttribute{
				MarkdownDescription: "Defines an *allow* rule entry in the policy",
				Required:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"users": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Users to whom this allow rule applies",
							Optional:            true,
						},
						"groups": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "User groups to whom this allow rule applies",
							Optional:            true,
						},
						"roles": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Ranger roles to which this allow rule applies",
							Optional:            true,
						},
						"permissions": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "The list of access actions allowed",
							Required:            true,
						},
						"delegate_admin": schema.BoolAttribute{
							MarkdownDescription: "Whether the users/groups in this rule are allowed to further delegate (grant) this permission to others",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
						},
						"conditions": schema.MapAttribute{
							ElementType:         types.ListType{ElemType: types.StringType},
							MarkdownDescription: "Additional Ranger conditions for this rule (advanced use)",
							Optional:            true,
						},
					},
				},
			},
			"deny_item": schema.ListNestedAttribute{
				MarkdownDescription: "Defines a *deny* rule entry in the policy",
				Optional:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"users": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Users to whom this deny rule applies",
							Optional:            true,
						},
						"groups": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "User groups to whom this deny rule applies",
							Optional:            true,
						},
						"roles": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "Ranger roles to which this deny rule applies",
							Optional:            true,
						},
						"permissions": schema.ListAttribute{
							ElementType:         types.StringType,
							MarkdownDescription: "The list of access actions denied",
							Required:            true,
						},
						"delegate_admin": schema.BoolAttribute{
							MarkdownDescription: "Whether the users/groups in this rule are allowed to further delegate (grant) this permission to others",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
						},
						"conditions": schema.MapAttribute{
							ElementType:         types.ListType{ElemType: types.StringType},
							MarkdownDescription: "Additional Ranger conditions for this rule (advanced use)",
							Optional:            true,
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *rangerPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}

// Create creates a new Ranger policy.
func (r *rangerPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan RangerPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert the plan to a Ranger policy
	policy, diags := r.convertModelToPolicy(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Prepare for API request
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Ranger Policy",
			fmt.Sprintf("Could not marshal policy JSON: %s", err),
		)
		return
	}

	url := fmt.Sprintf("%s/service/public/v2/api/policy", r.client.Endpoint)
	request, err := http.NewRequest("POST", url, strings.NewReader(string(policyJSON)))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return
	}

	request.Header.Set("Authorization", r.client.AuthHeader)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	// Execute the API request
	response, err := r.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return
	}
	defer response.Body.Close()

	// Check the response
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		resp.Diagnostics.AddError(
			"Error Creating Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return
	}

	// Decode the response
	var createdPolicy Policy
	err = json.NewDecoder(response.Body).Decode(&createdPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Ranger Policy",
			fmt.Sprintf("Could not decode API response: %s", err),
		)
		return
	}

	// Update the plan with the created policy ID
	plan.ID = types.StringValue(fmt.Sprintf("%d", createdPolicy.ID))

	// Update the terraform state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Created Ranger policy", map[string]interface{}{
		"id":   createdPolicy.ID,
		"name": createdPolicy.Name,
	})
}

// Read reads the Ranger policy from the API.
func (r *rangerPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state RangerPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If we don't have an ID, the policy was never created or was deleted
	if state.ID.IsNull() {
		resp.State.RemoveResource(ctx)
		return
	}

	// Prepare for API request
	url := fmt.Sprintf("%s/service/public/v2/api/policy/%s", r.client.Endpoint, state.ID.ValueString())
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return
	}

	request.Header.Set("Authorization", r.client.AuthHeader)
	request.Header.Set("Accept", "application/json")

	// Execute the API request
	response, err := r.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return
	}
	defer response.Body.Close()

	// Check if the policy exists
	if response.StatusCode == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}

	// Check for other errors
	if response.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return
	}

	// Decode the response
	var policy Policy
	err = json.NewDecoder(response.Body).Decode(&policy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Ranger Policy",
			fmt.Sprintf("Could not decode API response: %s", err),
		)
		return
	}

	// Convert the policy to the model
	model, diags := r.convertPolicyToModel(ctx, policy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update the terraform state
	diags = resp.State.Set(ctx, model)
	resp.Diagnostics.Append(diags...)
}

// Update updates an existing Ranger policy.
func (r *rangerPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan RangerPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert the plan to a Ranger policy
	policy, diags := r.convertModelToPolicy(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set the policy ID for the update
	policyID := plan.ID.ValueString()
	id, err := parseInt64(policyID)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("Could not parse policy ID: %s", err),
		)
		return
	}
	policy.ID = id

	// Prepare for API request
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("Could not marshal policy JSON: %s", err),
		)
		return
	}

	url := fmt.Sprintf("%s/service/public/v2/api/policy/%s", r.client.Endpoint, policyID)
	request, err := http.NewRequest("PUT", url, strings.NewReader(string(policyJSON)))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return
	}

	request.Header.Set("Authorization", r.client.AuthHeader)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	// Execute the API request
	response, err := r.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return
	}
	defer response.Body.Close()

	// Check the response
	if response.StatusCode != http.StatusOK {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return
	}

	// Decode the response to ensure it was successful
	var updatedPolicy Policy
	err = json.NewDecoder(response.Body).Decode(&updatedPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Ranger Policy",
			fmt.Sprintf("Could not decode API response: %s", err),
		)
		return
	}

	// Update the terraform state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Info(ctx, "Updated Ranger policy", map[string]interface{}{
		"id":   updatedPolicy.ID,
		"name": updatedPolicy.Name,
	})
}

// Delete deletes a Ranger policy.
func (r *rangerPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state RangerPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	policyID := state.ID.ValueString()
	url := fmt.Sprintf("%s/service/public/v2/api/policy/%s", r.client.Endpoint, policyID)

	// Prepare for API request
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Ranger Policy",
			fmt.Sprintf("Could not create request: %s", err),
		)
		return
	}

	request.Header.Set("Authorization", r.client.AuthHeader)

	// Execute the API request
	response, err := r.client.Client.Do(request)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Ranger Policy",
			fmt.Sprintf("Could not execute API request: %s", err),
		)
		return
	}
	defer response.Body.Close()

	// Check if the API call was successful
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		resp.Diagnostics.AddError(
			"Error Deleting Ranger Policy",
			fmt.Sprintf("API returned unexpected status code: %d", response.StatusCode),
		)
		return
	}

	tflog.Info(ctx, "Deleted Ranger policy", map[string]interface{}{
		"id": policyID,
	})
}

// ImportState imports a Ranger policy by ID.
func (r *rangerPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper functions

// convertModelToPolicy converts a Terraform model to a Ranger policy.
func (r *rangerPolicyResource) convertModelToPolicy(ctx context.Context, model RangerPolicyResourceModel) (Policy, diag.Diagnostics) {
	var diags diag.Diagnostics
	policy := Policy{
		Name:           model.Name.ValueString(),
		Service:        model.Service.ValueString(),
		IsEnabled:      model.IsEnabled.ValueBool(),
		IsAuditEnabled: model.IsAuditEnabled.ValueBool(),
		PolicyType:     model.PolicyType.ValueInt64(),
		Resources:      make(map[string]PolicyResources),
	}

	if !model.Description.IsNull() {
		policy.Description = model.Description.ValueString()
	}

	// Convert resources
	for _, res := range model.Resources {
		resType := res.Type.ValueString()
		valuesStrings := make([]string, 0, len(res.Values))
		for _, val := range res.Values {
			valuesStrings = append(valuesStrings, val.ValueString())
		}

		policy.Resources[resType] = PolicyResources{
			Values:      valuesStrings,
			IsExclude:   res.IsExclude.ValueBool(),
			IsRecursive: res.IsRecursive.ValueBool(),
		}
	}

	// Convert policy items (allow rules)
	if len(model.PolicyItems) > 0 {
		policy.PolicyItems = make([]PolicyItem, 0, len(model.PolicyItems))
		for _, item := range model.PolicyItems {
			policyItem, itemDiags := convertPolicyItemModel(item)
			diags.Append(itemDiags...)
			policy.PolicyItems = append(policy.PolicyItems, policyItem)
		}
	}

	// Convert deny policy items
	if len(model.DenyItems) > 0 {
		policy.DenyPolicyItems = make([]PolicyItem, 0, len(model.DenyItems))
		for _, item := range model.DenyItems {
			policyItem, itemDiags := convertPolicyItemModel(item)
			diags.Append(itemDiags...)
			policy.DenyPolicyItems = append(policy.DenyPolicyItems, policyItem)
		}
	}

	return policy, diags
}

// convertPolicyToModel converts a Ranger policy to a Terraform model.
func (r *rangerPolicyResource) convertPolicyToModel(ctx context.Context, policy Policy) (RangerPolicyResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	model := RangerPolicyResourceModel{
		ID:             types.StringValue(fmt.Sprintf("%d", policy.ID)),
		Name:           types.StringValue(policy.Name),
		Service:        types.StringValue(policy.Service),
		Description:    types.StringValue(policy.Description),
		IsEnabled:      types.BoolValue(policy.IsEnabled),
		IsAuditEnabled: types.BoolValue(policy.IsAuditEnabled),
		PolicyType:     types.Int64Value(policy.PolicyType),
	}

	// Convert resources
	resources := make([]RangerPolicyResourcesModel, 0)
	for resType, resValue := range policy.Resources {
		values := make([]types.String, 0, len(resValue.Values))
		for _, val := range resValue.Values {
			values = append(values, types.StringValue(val))
		}

		resources = append(resources, RangerPolicyResourcesModel{
			Type:        types.StringValue(resType),
			Values:      values,
			IsExclude:   types.BoolValue(resValue.IsExclude),
			IsRecursive: types.BoolValue(resValue.IsRecursive),
		})
	}
	model.Resources = resources

	// Convert policy items (allow rules)
	policyItems := make([]RangerPolicyItemModel, 0, len(policy.PolicyItems))
	for _, item := range policy.PolicyItems {
		policyItem, itemDiags := convertPolicyItem(item)
		diags.Append(itemDiags...)
		policyItems = append(policyItems, policyItem)
	}
	model.PolicyItems = policyItems

	// Convert deny policy items
	denyItems := make([]RangerPolicyItemModel, 0, len(policy.DenyPolicyItems))
	for _, item := range policy.DenyPolicyItems {
		policyItem, itemDiags := convertPolicyItem(item)
		diags.Append(itemDiags...)
		denyItems = append(denyItems, policyItem)
	}
	model.DenyItems = denyItems

	return model, diags
}

// convertPolicyItemModel converts a Terraform policy item model to a Ranger policy item.
func convertPolicyItemModel(itemModel RangerPolicyItemModel) (PolicyItem, diag.Diagnostics) {
	var diags diag.Diagnostics
	policyItem := PolicyItem{
		DelegateAdmin: itemModel.DelegateAdmin.ValueBool(),
	}

	// Convert users
	if len(itemModel.Users) > 0 {
		users := make([]string, 0, len(itemModel.Users))
		for _, user := range itemModel.Users {
			users = append(users, user.ValueString())
		}
		policyItem.Users = users
	}

	// Convert groups
	if len(itemModel.Groups) > 0 {
		groups := make([]string, 0, len(itemModel.Groups))
		for _, group := range itemModel.Groups {
			groups = append(groups, group.ValueString())
		}
		policyItem.Groups = groups
	}

	// Convert roles
	if len(itemModel.Roles) > 0 {
		roles := make([]string, 0, len(itemModel.Roles))
		for _, role := range itemModel.Roles {
			roles = append(roles, role.ValueString())
		}
		policyItem.Roles = roles
	}

	// Convert permissions to accesses
	if len(itemModel.Permissions) > 0 {
		accesses := make([]Access, 0, len(itemModel.Permissions))
		for _, perm := range itemModel.Permissions {
			accesses = append(accesses, Access{
				Type:      perm.ValueString(),
				IsAllowed: true,
			})
		}
		policyItem.Accesses = accesses
	}

	// Convert conditions (if any)
	if len(itemModel.Conditions) > 0 {
		conditions := make([]map[string]interface{}, 0)
		for condType, condValues := range itemModel.Conditions {
			values := make([]string, 0, len(condValues))
			for _, val := range condValues {
				values = append(values, val.ValueString())
			}

			condition := map[string]interface{}{
				"type":   condType,
				"values": values,
			}
			conditions = append(conditions, condition)
		}
		policyItem.Conditions = conditions
	}

	return policyItem, diags
}

// convertPolicyItem converts a Ranger policy item to a Terraform policy item model.
func convertPolicyItem(item PolicyItem) (RangerPolicyItemModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	policyItemModel := RangerPolicyItemModel{
		DelegateAdmin: types.BoolValue(item.DelegateAdmin),
		Conditions:    make(map[string][]types.String),
	}

	// Convert users
	users := make([]types.String, 0, len(item.Users))
	for _, user := range item.Users {
		users = append(users, types.StringValue(user))
	}
	policyItemModel.Users = users

	// Convert groups
	groups := make([]types.String, 0, len(item.Groups))
	for _, group := range item.Groups {
		groups = append(groups, types.StringValue(group))
	}
	policyItemModel.Groups = groups

	// Convert roles
	roles := make([]types.String, 0, len(item.Roles))
	for _, role := range item.Roles {
		roles = append(roles, types.StringValue(role))
	}
	policyItemModel.Roles = roles

	// Convert accesses to permissions
	permissions := make([]types.String, 0, len(item.Accesses))
	for _, access := range item.Accesses {
		if access.IsAllowed {
			permissions = append(permissions, types.StringValue(access.Type))
		}
	}
	policyItemModel.Permissions = permissions

	// Convert conditions (if any)
	for _, condition := range item.Conditions {
		condType, ok := condition["type"].(string)
		if !ok {
			continue
		}

		condValues, ok := condition["values"].([]interface{})
		if !ok {
			continue
		}

		values := make([]types.String, 0, len(condValues))
		for _, val := range condValues {
			if strVal, ok := val.(string); ok {
				values = append(values, types.StringValue(strVal))
			}
		}

		policyItemModel.Conditions[condType] = values
	}

	return policyItemModel, diags
}

// Helper function to parse int64 from string
func parseInt64(s string) (int64, error) {
	var i int64
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
