package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/Khan/genqlient/generate"
	"github.com/Khan/genqlient/graphql"
	"github.com/vektah/gqlparser/gqlerror"
)

const (
	OpsmxAuthHeader = "X-OpsMx-Auth"
	graphqlEndpoint = "http://localhost:8080/graphql"
	Token           = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJPcHNNeCIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6WyJzc2Qub3BzbXguaW8iXSwic3NkLm9wc214LmlvIjp7InR5cGUiOiJpbnRlcm5hbC1hY2NvdW50L3YxIiwiaXNBZG1pbiI6dHJ1ZX19.Z9n7UjQhX_sY2fRP7rRxNbShcmVhyjV2GT1rY1nsbhw"
	OrgId           = "e550c51d-9d83-4589-86a7-cb40a270c970"
)

func customGraphQlCall(body []byte) error {
	httpClient := http.Client{}
	httpReq, err := http.NewRequest(
		http.MethodPost,
		graphqlEndpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return errors.New("http.NewRequest: error: " + err.Error())
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-OpsMx-Auth", Token)

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return errors.New("httpClient.Do: error: " + err.Error())
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		var respBody []byte
		respBody, err = io.ReadAll(httpResp.Body)
		if err != nil {
			respBody = []byte(fmt.Sprintf("<unreadable: %v>", err))
		}
		return fmt.Errorf("returned error %v: %s", httpResp.Status, respBody)
	}

	responseBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return errors.New("io.ReadAll: error: " + err.Error())
	}

	var resp Response
	err = json.Unmarshal(responseBytes, &resp)
	if err != nil {
		return fmt.Errorf("json.NewDecoder error %v: %s", err, httpResp.Body)
	}
	if len(resp.Errors) > 0 {
		return fmt.Errorf("resp.Errors error %v", resp.Errors)
	}
	return nil
}

type Response struct {
	Data       interface{}            `json:"data"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
	Errors     gqlerror.List          `json:"errors,omitempty"`
}

type PolicyDefinitionScript struct {
	PolicyId        string      `json:"policyId,omitempty" yaml:"policyId,omitempty"`
	OrgId           string      `json:"orgId,omitempty" yaml:"orgId,omitempty"`
	PolicyName      string      `json:"policyName,omitempty" yaml:"policyName,omitempty"`
	Category        string      `json:"category,omitempty" yaml:"category,omitempty"`
	Stage           string      `json:"stage,omitempty" yaml:"stage,omitempty"`
	Description     string      `json:"description,omitempty" yaml:"description,omitempty"`
	ScheduledPolicy bool        `json:"scheduled_policy,omitempty" yaml:"scheduledPolicy,omitempty"`
	DatasourceTool  []IDStruct  `json:"datasourceTool,omitempty" yaml:"datasourceTool,omitempty"`
	ScriptId        string      `json:"scriptId,omitempty" yaml:"scriptId,omitempty"`
	Variables       string      `json:"variables,omitempty" yaml:"variables,omitempty"`
	ConditionName   string      `json:"conditionName,omitempty" yaml:"conditionName,omitempty"`
	Suggestion      interface{} `json:"suggestion,omitempty" yaml:"suggestion,omitempty"`
}

type PolicyEnforcementScript struct {
	PolicyId       string `json:"policyId,omitempty" yaml:"policyId,omitempty"`
	Severity       string `json:"severity,omitempty" yaml:"severity,omitempty"`
	Action         string `json:"action,omitempty" yaml:"action,omitempty"`
	ConditionValue string `json:"conditionValue,omitempty" yaml:"conditionValue,omitempty"`
	Status         bool   `json:"status,omitempty" yaml:"status,omitempty"`
}

type IDStruct struct {
	Id string `json:"id,omitempty" yaml:"id,omitempty"`
}

func main() {

	req := &graphql.Request{
		OpName: "AddDatasourceTool",
		Query:  addToolsQuery,
	}
	body, err := json.Marshal(req)
	if err != nil {
		fmt.Println("json.Marshal: error: ", err.Error())
		return
	}

	if err := customGraphQlCall(body); err != nil {
		fmt.Println(err.Error())
		return
	}

	req = &graphql.Request{
		OpName: "AddFeatureMode",
		Query:  featureMode,
	}

	body, err = json.Marshal(req)
	if err != nil {
		fmt.Println("json.Marshal: error: ", err.Error())
		return
	}

	if err := customGraphQlCall(body); err != nil {
		fmt.Println(err.Error())
		return
	}

	var addPoliciesDef []*AddPolicyDefinitionInput

	for _, policyDef := range policyDefinition {

		var policyDefScript PolicyDefinitionScript
		if err := json.Unmarshal([]byte(policyDef), &policyDefScript); err != nil {
			fmt.Println("ERROR JSON UNMARSHAL POLICY DEF ", err.Error())
			fmt.Println(policyDef)
			continue
		}

		scriptID, _ := strconv.Atoi(policyDefScript.ScriptId)

		now := time.Now().UTC()
		policy := AddPolicyDefinitionInput{
			Id: policyDefScript.PolicyId,
			OwnerOrg: &OrganizationRef{
				Id: OrgId,
			},
			CreatedAt:       &now,
			UpdatedAt:       &now,
			PolicyName:      policyDefScript.PolicyName,
			Category:        policyDefScript.Category,
			Stage:           policyDefScript.Stage,
			Description:     policyDefScript.Description,
			Script:          scriptMap[scriptID],
			ScheduledPolicy: &policyDefScript.ScheduledPolicy,
			Variables:       policyDefScript.Variables,
			ConditionName:   policyDefScript.ConditionName,
		}
		var dataSourceTools []*DatasourceToolRef
		for _, tool := range policyDefScript.DatasourceTool {
			dataSourceTools = append(dataSourceTools, &DatasourceToolRef{
				Id: tool.Id,
			})
		}
		policy.DatasourceTool = dataSourceTools

		addPoliciesDef = append(addPoliciesDef, &policy)
	}

	if _, err := AddPolicyDefinition(context.TODO(), NewGraphqlClient(), addPoliciesDef); err != nil {
		fmt.Println("err: AddPolicyDefinition : ", err.Error())
	}

	var allPolicyEnf []*AddPolicyEnforcementInput

	for _, enf := range policyEnforcement {
		var policyEnfScript PolicyEnforcementScript
		if err := json.Unmarshal([]byte(enf), &policyEnfScript); err != nil {
			fmt.Println("ERROR JSON UNMARSHAL POLICY Enf ", err.Error())
		}

		now := time.Now().UTC()

		policyEnf := AddPolicyEnforcementInput{
			Policy: &PolicyDefinitionRef{
				Id: policyEnfScript.PolicyId,
			},
			EnforcedOrg: &OrganizationRef{
				Id: OrgId,
			},
			Status:         &policyEnfScript.Status,
			Severity:       mapSeverity(policyEnfScript.Severity),
			Action:         policyEnfScript.Action,
			ConditionValue: policyEnfScript.ConditionValue,
			CreatedAt:      &now,
			UpdatedAt:      &now,
		}

		allPolicyEnf = append(allPolicyEnf, &policyEnf)
	}

	if _, err := AddPolicyEnforcement(context.TODO(), NewGraphqlClient(), allPolicyEnf); err != nil {
		fmt.Println("err: AddPolicyEnforcement : ", err.Error())
	}

}

type authedTransport struct {
	token   string
	wrapped http.RoundTripper
}

func (t *authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(OpsmxAuthHeader, t.token)
	return t.wrapped.RoundTrip(req)
}

func NewGraphqlClient() graphql.Client {

	httpClient := http.Client{
		Timeout: 30 * time.Second,
		Transport: &authedTransport{
			token:   Token,
			wrapped: http.DefaultTransport,
		},
	}

	return graphql.NewClient(graphqlEndpoint, &httpClient)
}

func mapSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	case "none":
		return SeverityNone
	default:
		print(s)
		return SeverityUnknown
	}
}
