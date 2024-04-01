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
	Token           = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA1Nzk1MDUyLTcyYzAtNDk1Ni1hODc1LWEzZmUzNjJmMjk4MCIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJPcHNNeCIsImF1ZCI6WyJzc2Qub3BzbXguaW8iXSwiZXhwIjoxNzExNzE5NTg3LCJuYmYiOjE3MTE2OTc5ODcsImp0aSI6Ijg0NWQ2ODRlLWVkOWYtMTFlZS05YWQ4LTk2ZGUyMDEzYTIzNiIsInNzZC5vcHNteC5pbyI6eyJ0eXBlIjoiaW50ZXJuYWwtYWNjb3VudC92MSIsImF1dGhvcml6YXRpb25zIjpbImFjY2Vzcy1kZ3JhcGgiXSwic2VydmljZSI6InNzZC1vcGEifX0.i1k9qSGRwGGgHXidTPXB0Hir6lNQKyIcr7Ya3nC0-k1BjEJFwlu5BfyooNxj6XcOK8z9r4b0_o-e5G7_ruxP1sw5AWe5Whl4J3Mo_lg3GmGi2D02dgjPHxyQtqq3DaxIBZ1hniqJG7PGthWW6D_BWbNoB1Q3UlcZsVxNM2Q_Z59-FiqJqwMT0BPaL5FcGS0G9FDXLR-ykKZocJ63Udo_MwfeQbKyMIYE9vZwvoanaq3Z3EZmX7dkUs6NcGw9IHLDMMRcwMYQXs3NVs2VgT2tj3E5G64IZ13jrKOywkRfiKJcGB3NnsZ69amKSPF1y0OgMp-Pz4vbvFMdVgvxAIjV6A"
	OrgId           = "78196327-04f8-4555-a2a4-ba10b20d7298"
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
