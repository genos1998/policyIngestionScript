package main

const featureMode = `
mutation AddFeatureMode {
    addFeatureMode(
        input: [
        {
            id: "1"
            organization: { id: "78196327-04f8-4555-a2a4-ba10b20d7298" }
            enabled: true
            createdAt: "2024-02-21T12:30:00"
            updatedAt: "2024-02-21T12:30:00"
            type: "trivy"
            scan: "vulnerabilityscan"
            category: "scanningtool"
        },
        {
            id: "2"
            organization: { id: "78196327-04f8-4555-a2a4-ba10b20d7298" }
            enabled: true
            createdAt: "2024-02-21T12:30:00"
            updatedAt: "2024-02-21T12:30:00"
            type: "trivy"
            scan: "secretscanforcontainers"
            category: "scanningtool"
        },
        {
            id: "3"
            organization: { id: "78196327-04f8-4555-a2a4-ba10b20d7298" }
            enabled: true
            createdAt: "2024-02-21T12:30:00"
            updatedAt: "2024-02-21T12:30:00"
            type: "trivy"
            scan: "licensescan"
            category: "scanningtool"
        },
        {
            id: "4"
            organization: { id: "78196327-04f8-4555-a2a4-ba10b20d7298" }
            enabled: true
            createdAt: "2024-02-21T12:30:00"
            updatedAt: "2024-02-21T12:30:00"
            type: "trivy"
            scan: "secretscanforsource"
            category: "scanningtool"
        },
        {
            id: "5"
            organization: { id: "78196327-04f8-4555-a2a4-ba10b20d7298" }
            enabled: false
            createdAt: "2024-02-21T12:30:00"
            updatedAt: "2024-02-21T12:30:00"
            type: "trivy"
            scan: "helmscan"
            category: "scanningtool"
        }
        ]
    ) {
        numUids
    }
}
`

const addToolsQuery = `
mutation AddDatasourceTool {
	addDatasourceTool(input: [
	   { id: "1", name: "github" },
	   { id: "2", name: "gitlab" },
	   { id: "3", name: "bitbucket" },
	   { id: "4", name: "jenkins" },
	   { id: "5", name: "docker" },
	   { id: "6", name: "quay" },
	   { id: "7", name: "jfrog" },
	   { id: "8", name: "argo" },
	   { id: "9", name: "spinnaker" },
	   { id: "10", name: "kubernetes" },
	   { id: "11", name: "cis-kubescape" },
	   { id: "12", name: "mitre-kubescape" },
	   { id: "13", name: "nsa-kubescape" },
	   { id: "14", name: "helm" },
	   { id: "15", name: "openssf" },
	   { id: "16", name: "trivy" },
	   { id: "17", name: "snyk" },
	   { id: "18", name: "grype" },
	   { id: "19", name: "sonarqube" },
	   { id: "20", name: "semgrep" },
	   { id: "21", name: "graphql" }
   ]) {
	   numUids
   }
}
`

var scriptMap = map[int]string{
	69: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	72: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	166: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	217: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	292: `
	package opsmx
	import future.keywords.in
	
	default allow = false

	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/hooks"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository webhook configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get webhook configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read webhook configuration."
	error := "Mentioned branch for Repository not found while trying to fetch webhook configuration."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}

	default ssl_disabled_hooks = []
	ssl_disabled_hooks = [response.body[i].id | response.body[i].enable_ssl_verification == false]

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
	count(ssl_disabled_hooks) > 0
	msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
	error := ""
	sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner,input.metadata.repository])
	}`,
	26: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	37: `
	package opsmx
	import future.keywords.in
	default approved_servers_count = 0
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }] {
	  approved_servers_count = count(input.metadata.ssd_secret.build_access_config.credentials)
	  approved_servers_count == 0
	  msg:=""
	  sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs to strengthen artifact validation during the deployment process."
	  error:="The essential list of approved build URLs remains unspecified"
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
	  build_url = split(input.metadata.build_url, "/")[2]
	  list_of_approved_servers = [split(input.metadata.ssd_secret.build_access_config.credentials[i].url, "/")[2] |input.metadata.ssd_secret.build_access_config.credentials[i].url != ""]
	
	  not build_url in list_of_approved_servers
	  msg:=sprintf("The artifact has not been sourced from an approved build server.\nPlease verify the artifacts origin against the following approved build URLs: %v", [concat(",", list_of_approved_servers)])
	  sugg:="Ensure the artifact is sourced from an approved build server."
	  error:=""
	}`,
	44: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	259: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
}`,
	92: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	100: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	167: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	244: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	117: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	173: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	180: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	187: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	284: `
	package opsmx
	default medium_severities = []
	
	default multi_alert = false
	default exists_alert = false
	
	exists_alert = check_if_medium_alert_exists
	multi_alert = check_if_multi_alert
	
	check_if_medium_alert_exists = exists_flag {
	  medium_severities_counter = count(input.metadata.results[0].MediumSeverity)
	  medium_severities_counter > 0
	  exists_flag = true
	}
	
	check_if_multi_alert() = multi_flag {
	  medium_severities_counter = count(input.metadata.results[0].MediumSeverity)
	  medium_severities_counter > 1
	  multi_flag = true
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  check_if_medium_alert_exists
	  check_if_multi_alert
	  
	  some i
	  rule = input.metadata.results[0].MediumSeverity[i].RuleID
	  title = input.metadata.results[0].MediumSeverity[i].Title
	  targets = concat(",\n", input.metadata.results[0].MediumSeverity[i].TargetResources)
	  resolution = input.metadata.results[0].MediumSeverity[i].Resolution
	  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of medium severity:\n %v", [rule, title, targets])
	  sugg := resolution
	  error := ""
	}`,
	53: `
	package opsmx

	deny[msg] {
	  not is_update(input.request)
	
	  c := input_containers[_]
	  input_allow_privilege_escalation(c)
	  msg := sprintf("Privilege escalation container is not allowed: %v", [c.name])
	}
	
	input_allow_privilege_escalation(c) {
	  not has_field(c, "securityContext")
	}
	input_allow_privilege_escalation(c) {
	  not c.securityContext.allowPrivilegeEscalation == false
	}
	input_containers[c] {
	  c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
	  c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
	  c := input.request.object.spec.ephemeralContainers[_]
	}
	
	has_field(object, field) = true {
	  object[field]
	}
	
	is_update(review) {
	  review.operation == "UPDATE"
	}`,
	82: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	109: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	48: `
	package opsmx

        severity = "high"
        default findings_count = 0

        complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]	)
        request = {	
                "method": "GET",
                "url": complete_url
        }

        response = http.send(request)

        findings_count = response.body.totalFindings

        deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
          findings_count > 0
          msg := sprintf("The github repository %v/%v contains %v findings of %v severity.", [input.metadata.owner, input.metadata.repository, findings_count, severity])
          sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
          error := ""
        }`,
	169: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	115: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	174: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	177: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	200: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	234: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	24: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	49: `
	package opsmx

        severity = "medium"
        default findings_count = 0

        complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]	)
        request = {	
                "method": "GET",
                "url": complete_url
        }

        response = http.send(request)

        findings_count = response.body.totalFindings

        deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
          findings_count > 0
          msg := sprintf("The github repository %v/%v contains %v findings of %v severity.", [input.metadata.owner, input.metadata.repository, findings_count, severity])
          sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
          error := ""
        }`,
	87: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	291: `
	package opsmx
	import future.keywords.in
	
	default allow = false

	request_components = [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/user"]

	request_url = concat("",request_components)

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.body.two_factor_enabled == false
	msg := sprintf("Gitlab Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
	sugg := sprintf("Adhere to the company policy by enabling 2FA for users of %s organisation.",[input.metadata.owner])
	error := ""
	}`,
	4: `
	package opsmx

	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch,"protection"]
	request_url = concat("/", request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	raw_body = response.raw_body
	parsed_body = json.unmarshal(raw_body)
	
	allow {
	  response.status_code = 200
	}
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 404
	  msg := ""
	  sugg := "Kindly provide the accurate repository name, organization, and branch details. Also, check if branch protection policy is configured."
	  error := sprintf("%v %v",[response.status_code,response.body.message])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 401
	  msg := ""
	  sugg := "Please provide the Appropriate Git Token for the User"
	  error := sprintf("%s %v", [parsed_body.message,response.status])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 500
	  msg := "Internal Server Error"
	  sugg := ""
	  error := "GitHub is not reachable"
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.allow_deletions.enabled = true
	  msg := sprintf("Github repo %v is having policy and branch cannot be deleted", [input.metadata.repository])
	  sugg := sprintf("Disable branch deletion in %s Github repo to align with the company policy", [input.metadata.repository])
	  error := ""
	}`,
	13: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	101: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	165: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	211: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	64: `
	package opsmx

	deny[msg] {
		not is_update(input.request)

		c := input_containers[_]
		input_read_only_root_fs(c)
		msg := sprintf("only read-only root filesystem container is allowed: %v", [c.name])
	}

	input_read_only_root_fs(c) {
		not has_field(c, "securityContext")
	}
	input_read_only_root_fs(c) {
		not c.securityContext.readOnlyRootFilesystem == true
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	has_field(object, field) = true {
		object[field]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	129: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	140: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	265: `
	package opsmx
	import future.keywords.in
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.parent_repo != ""
	
	  parent_repo_owner != input.metadata.owner
	  msg := sprintf("The pipeline uses a forked repo from a different organization %s from %s.", [input.metadata.parent_repo, input.metadata.owner])
	  sugg := "Refrain from running pipelines originating from forked repos not belonging to the same organization."
	  error := ""
	}`,
	30: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	45: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	57: `
	package opsmx

	# Block if forbidden
	deny[msg] {
	# spec.securityContext.sysctls field is immutable.
	not is_update(input.request)

	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	forbidden_sysctl(sysctl)
	msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.forbiddenSysctls])
	}

	# Block if not explicitly allowed
	deny[msg] {
	not is_update(input.request)
	sysctl := input.request.object.spec.securityContext.sysctls[_].name
	not allowed_sysctl(sysctl)
	msg := sprintf("The sysctl %v is not explicitly allowed, pod: %v. Allowed sysctls: %v", [sysctl, input.request.object.metadata.name, input.parameters.allowedSysctls])
	}

	# * may be used to forbid all sysctls
	forbidden_sysctl(sysctl) {
	input.parameters.forbiddenSysctls[_] == "*"
	}

	forbidden_sysctl(sysctl) {
	input.parameters.forbiddenSysctls[_] == sysctl
	}

	forbidden_sysctl(sysctl) {
	forbidden := input.parameters.forbiddenSysctls[_]
	endswith(forbidden, "*")
	startswith(sysctl, trim_suffix(forbidden, "*"))
	}

	# * may be used to allow all sysctls
	allowed_sysctl(sysctl) {
	input.parameters.allowedSysctls[_] == "*"
	}

	allowed_sysctl(sysctl) {
	input.parameters.allowedSysctls[_] == sysctl
	}

	allowed_sysctl(sysctl) {
	allowed := input.parameters.allowedSysctls[_]
	endswith(allowed, "*")
	startswith(sysctl, trim_suffix(allowed, "*"))
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	8: `
package opsmx
severities = ["CRITICAL"]
vuln_id = input.conditions[0].condition_value
vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
deny[msg]{
some i
inputSeverity = severities[i]
some j
vuln_severity[j] == inputSeverity
msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
}
`,
	12: `
	package opsmx


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.build_image_sha == "" 
		msg = ""
		sugg = "Ensure that build platform is integrated with SSD."
		error = "Complete Build Artifact information could not be identified."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.image_sha == ""
		msg = ""
		sugg = "Ensure that deployment platform is integrated with SSD usin Admission Controller."
		error = "Artifact information could not be identified from Deployment Environment."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
	}`,
	289: `
	package opsmx

	import future.keywords.in
	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/members"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository members due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository members."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository members."
	error := "Mentioned branch for Repository not found while trying to fetch repository members."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}

	default denial_list = false

	denial_list = matched_users

	matched_users[user] {
		users := [response.body[i].username | response.body[i].access_level == 50]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
	counter := count(denial_list)
	counter > 0
	denial_list_str := concat(", ", denial_list)
	msg := sprintf("Owner access of Gitlab Repository is granted to bot users. \n Number of bot users having owner access: %v. \n Name of bots having owner access: %v", [counter, denial_list_str])
	sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	error := ""
	}`,
	144: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	156: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	168: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	175: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	231: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	74: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	79: `
	package opsmx
	import future.keywords.in
	
	deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
	  policy = input.conditions[0].condition_name
	  
	  input.metadata.results[i].control_title == policy
	  control_struct = input.metadata.results[i]
	  failed_resources = control_struct.failed_resources
	  counter = count(failed_resources)
	  counter > 0
	  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
	  error := ""
	  suggestion := input.metadata.suggestion
	}`,
	103: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	290: `
	package opsmx
	import future.keywords.in
	
	default allow = false

	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/repository/files/SECURITY.md?ref=", input.metadata.branch])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := sprintf("SECURITY.md file not found in branch %v of repository %v.", [input.metadata.branch, input.metadata.repository])
	sugg := "Adhere to security standards and configure SECURITY.md file in the repository."
	error := ""
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}`,
	257: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
}`,
	276: `
	package opsmx

	default secrets_count = 0
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.owner, input.metadata.repository, input.metadata.build_id, "codeScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for %v/%v Github repository for branch %v.\nBelow are the secrets identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, concat(",\n", medium_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	279: `
	package opsmx

	default secrets_count = 0
	
	default image_name = ""
	
	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.image_sha, "imageScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	critical_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "CRITICAL"]
	secrets_count = count(critical_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for Artifact %v:%v.\nBelow are the secrets identified:\n %v", [image_name, input.metadata.image_tag, concat(",\n", critical_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}
	`,
	105: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	134: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	152: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	251: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	11: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "actions", "permissions", "workflow"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check Repository Workflow Permissions."
	  error := "401 Unauthorized."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository workflow permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := "Mentioned Repository not found while trying to fetch repository workflow permissions."
	  sugg := "Kindly check if the repository provided is correct."
	  error := "Repository name is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := "Unable to fetch repository workflow permissions."
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository workflow permissions.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.body.default_workflow_permissions != "read"
	  msg := sprintf("Default workflow permissions for Repository %v/%v is not set to read.", [input.metadata.owner, input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Repository %v/%v to read only.", [input.metadata.owner, input.metadata.repository])
	  error := ""
	}`,
	29: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	68: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	81: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	108: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	122: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	255: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	17: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	76: `
	package opsmx
	severities = ["HIGH"]
	vuln_id = input.conditions[0].condition_value
	vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
	deny[msg]{
	some i
	inputSeverity = severities[i]
	some j
	vuln_severity[j] == inputSeverity
	msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
	}
	`,
	145: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	137: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	6: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"orgs", input.metadata.owner]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	raw_body = response.raw_body
	parsed_body = json.unmarshal(raw_body)
	mfa_enabled = response.body.two_factor_requirement_enabled
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  error := "Unauthorized to check organisation configuration due to Bad Credentials."
	  msg := ""
	  sugg := "Kindly check the access token. It must have enough permissions to get organisation configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  error := "Mentioned Organisation not found while trying to fetch org configuration. The repository does not belong to an organisation."
	  sugg := "Kindly check if the organisation provided is correct and the access token has rights to read organisation configuration.Also, verify if the repository belongs to an organisation."
	  msg := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  mfa_enabled == null
	  msg := sprintf("Github Organisation %v doesnt have the mfa enabled.", [input.metadata.owner])
	  sugg := sprintf("Adhere to the company policy by enabling 2FA for %s.",[input.metadata.owner])
	  error := ""
	}`,
	268: `sample script`,
	278: `
	package opsmx

	default secrets_count = 0
	
	default image_name = ""
	
	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.image_sha, "imageScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	high_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "HIGH"]
	secrets_count = count(high_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for Artifact %v:%v.\nBelow are the secrets identified:\n %v", [image_name, input.metadata.image_tag, concat(",\n", high_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	269: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  error := "Unauthorized to check repository configuration due to Bad Credentials."
	  msg := ""
	  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  error := "Repository not found or SBOM could not be fetched."
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration. Also, kindly verify if dependency tracking is enabled for the repository."
	  msg := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
		response.body.sbom = "" 
		error := sprintf("The SBOM could not be fetched, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.repository])
		sugg := "Please make sure there are some packages in the GitHub Repository."
		msg := ""
	}
	
	default pkg_without_version = []
	
	pkg_without_version = [pkg2.name | pkg2 := response.body.sbom.packages[_]
								pkg2.name != response.body.sbom.name
								not startswith(pkg2.name, "actions:")
								pkg2.versionInfo == ""]
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		count(pkg_without_version) != 0
		msg := sprintf("The GitHub repository %v/%v exhibits packages with inadequate versioning.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and mandate proper tagging and versioning for packages of %v/%v repository.", [input.metadata.owner, input.metadata.repository])
		error := ""
	}`,
	34: `
	package opsmx
	import future.keywords.in
	
	request_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "orgs", input.metadata.owner, "members?role=admin"])
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check organisation members."
	  sugg := "Kindly check the access token. It must have enough permissions to get organisation members."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read organisation members. Also check if the repository belongs to an organization."
	  error := "Mentioned branch for Repository not found while trying to fetch organisation members. Either Organisation/Repository name is incorrect or the repository does not belong to an organization."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch organisation members. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	default denial_list = false
	
	denial_list = matched_users
	
	matched_users[user] {
		users := [response.body[i].login | response.body[i].type == "User"]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
	  counter := count(denial_list)
	  counter > 0
	  denial_list_str := concat(", ", denial_list)
	  msg := sprintf("Owner access of Github Organization is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
	  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v Organization.", [input.metadata.owner])
	  error := ""
	}`,
	148: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	209: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	275: `
	package opsmx

	default secrets_count = 0
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.owner, input.metadata.repository, input.metadata.build_id, "codeScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	critical_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "CRITICAL"]
	secrets_count = count(critical_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for %v/%v Github repository for branch %v.\nBelow are the secrets identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, concat(",\n", critical_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	143: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	184: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	194: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	95: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	107: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	195: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	235: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	263: `
	package opsmx

	default allow = false
	
	repo_search = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.github_org, input.metadata.github_repo]
	repo_searchurl = concat("/",repo_search)
	
	branch_search = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch]
	branch_searchurl = concat("/",branch_search)
	
	protect_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.default_branch,"protection"]
	protect_url = concat("/",protect_components)
	
	token = input.metadata.ssd_secret.github.token
	
	repo_search_request = {
		"method": "GET",
		"url": repo_searchurl,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	branch_search_request = {
		"method": "GET",
		"url": branch_searchurl,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	protect_search_request = {
		"method": "GET",
		"url": protect_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(repo_search_request)
	
	branch_response = http.send(branch_search_request)
	
	branch_protect = http.send(protect_search_request)
	
	branch_check = response.body.default_branch
	
	AllowAutoMerge = response.body.allow_auto_merge
	
	delete_branch_on_merge = response.body.delete_branch_on_merge
	
	branch_protected = branch_response.body.protected
	
	RequiredReviewers = branch_protect.body.required_pull_request_reviews.required_approving_review_count
	
	AllowForcePushes = branch_protect.body.allow_force_pushes.enabled
	
	AllowDeletions = branch_response.body.allow_deletions.enabled
	
	RequiredSignatures = branch_protect.body.required_signatures.enabled
	
	EnforceAdmins = branch_protect.body.enforce_admins.enabled
	
	RequiredStatusCheck = branch_protect.body.required_status_checks.strict
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  branch_check = " "
	  msg := "Github does not have any branch"
	  sugg := "Please create a branch"
	  error := ""
	} 
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  AllowAutoMerge = true
	  msg := sprintf("The Auto Merge is enabled for the %s owner %s repo", [input.metadata.github_repo, input.metadata.default_branch])
	  sugg := "Please disable the Auto Merge"
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  delete_branch_on_merge = true
	  msg := "The branch protection policy that allows branch deletion is enabled."
	  sugg := sprintf("Please disable the branch deletion of branch %s of repo %s", [input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  branch_protected = false
	  msg := sprintf("Github repo %v and branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
	  sugg := sprintf("Make sure branch %v of %v repo has some branch policies", [input.metadata.github_repo,input.metadata.default_branch])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  RequiredReviewers = 0
	  msg := "The branch protection policy that mandates the minimum review for branch protection has been deactivated."
	  sugg := sprintf("Activate branch protection: pull request and minimum 1 approval before merging for branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  AllowForcePushes = true
	  msg := "The branch protection policy that allows force pushes is enabled."
	  sugg := sprintf("Please disable force push of branch %v of repo %v", [input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  AllowDeletions = true
	  msg := "The branch protection policy that allows branch deletion is enabled."
	  sugg := sprintf("Please disable the branch deletion of branch %v of repo %v",[input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  RequiredSignatures = true
	  msg := "The branch protection policy that requires signature is disabled."
	  sugg := sprintf("Please activate the mandatory GitHub signature policy for branch %v signatures of %v repo",[input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  EnforceAdmins = true
	  msg := sprintf("The branch protection policy that enforces status checks for repository administrators is disabled", [input.metadata.github_repo])
	  sugg := sprintf("Please activate the branch protection policy, dont by pass status checks for repository administrators of branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  RequiredStatusCheck = true
	  msg := sprintf("The branch protection policy that requires status check is disabled for the repo %s", [input.metadata.github_repo])
	  sugg := sprintf("Please activate the branch protection policy, requiring a need to be up-to-date with the base branch before merging for branch %s of %s repo",[input.metadata.default_branch,input.metadata.github_repo])
	  error := ""
	}`,
	283: `
	package opsmx
	default critical_severities = []
	
	default multi_alert = false
	default exists_alert = false
	
	exists_alert = check_if_critical_alert_exists
	multi_alert = check_if_multi_alert
	
	check_if_critical_alert_exists = exists_flag {
	  critical_severities_counter = count(input.metadata.results[0].CriticalSeverity)
	  critical_severities_counter > 0
	  exists_flag = true
	}
	
	check_if_multi_alert() = multi_flag {
	  critical_severities_counter = count(input.metadata.results[0].CriticalSeverity)
	  critical_severities_counter > 1
	  multi_flag = true
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  check_if_critical_alert_exists
	  check_if_multi_alert
	  
	  some i
	  rule = input.metadata.results[0].CriticalSeverity[i].RuleID
	  title = input.metadata.results[0].CriticalSeverity[i].Title
	  targets = concat(",\n", input.metadata.results[0].CriticalSeverity[i].TargetResources)
	  resolution = input.metadata.results[0].CriticalSeverity[i].Resolution
	  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of critical severity:\n %v", [rule, title, targets])
	  sugg := resolution
	  error := ""
	}
	`,
	16: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	65: `
	package opsmx

	deny[msg] {
	not is_update(input.request)

	volume_fields := {x | input.request.object.spec.volumes[_][x]; x != "name"}
	field := volume_fields[_]
	not input_volume_type_allowed(field)
	msg := sprintf("The volume type %v is not allowed, pod: %v. Allowed volume types: %v", [field, input.request.object.metadata.name, input.parameters.volumes])
	}

	# * may be used to allow all volume types
	input_volume_type_allowed(_) {
	input.parameters.volumes[_] == "*"
	}

	input_volume_type_allowed(field) {
	field == input.parameters.volumes[_]
	}

	is_update(request) {
	request.operation == "UPDATE"
	}`,
	146: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	147: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	191: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	286: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	default private_repo = ""

	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url, "api/v4/projects/", input.metadata.gitlab_project_id])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
	error := "Repository not found while trying to fetch Repository Configuration."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Github upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.body.visibility != "private"
	msg := sprintf("Gitlab Project %v is publically visible.", [input.metadata.repository])
	sugg := "Kindly adhere to security standards and change the visibility of the repository to private."
	error := ""
	}`,
	227: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	264: `
	package opsmx
	import future.keywords.in
	default approved_servers_count = 0
	default list_approved_user_str = []

	build_url = split(input.metadata.build_url, "/")[2]
	list_approved_user_str = {input.metadata.ssd_secret.build_access_config.credentials[i].approved_user | split(input.metadata.ssd_secret.build_access_config.credentials[i].url, "/")[2] == build_url}
	list_approved_users = split(list_approved_user_str[_], ",")
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }] {
	  approved_servers_count = count(input.metadata.ssd_secret.build_access_config.credentials)
	  approved_servers_count == 0
	  msg:=""
	  sugg:="Set the BuildAccessConfig.Credentials parameter with trusted build server URLs and users to strengthen artifact validation during the deployment process."
	  error:="The essential list of approved build URLs remains unspecified."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
	  list_approved_user_str == []
	  msg := ""
	  sugg := "Set the BuildAccessConfig.Credentials parameter with trusted build server URLs and users to strengthen artifact validation during the deployment process."
	  error := "The essential list of approved build users remains unspecified."
	}
	  
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  count(input.metadata.ssd_secret.build_access_config.credentials) > 0
	  not input.metadata.build_user in list_approved_users
	  msg:="The artifact has not been sourced from an approved user.\nPlease verify the artifacts origin."
	  sugg:="Ensure the artifact is sourced from an approved user."
	  error:=""
	}`,
	75: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	164: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	188: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	223: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	248: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	42: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentation 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	60: `
	package opsmx

	deny[msg] {
	not is_update(input.review)

	input_share_hostnamespace(input.request.object)
	msg := sprintf("Sharing the host namespace is not allowed: %v", [input.request.object.metadata.name])
	}

	input_share_hostnamespace(o) {
	o.spec.hostPID
	}
	input_share_hostnamespace(o) {
	o.spec.hostIPC
	}

	is_update(review) {
	review.operation == "UPDATE"
	}`,
	89: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	178: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	208: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	270: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository,"dependency-graph/sbom"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check repository configuration due to Bad Credentials."
	  error := "401 Unauthorized."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := "Repository SBOM not found while trying to fetch Repository Configuration."
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration. Also, check if dependency mapping is enabled."
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := "Unable to fetch repository configuration."
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}] {
		response.body.sbom = "" 
		error := sprintf("The SBOM could not be fetched, hence Centralized package manager settings Policy cannot be validated.", [input.metadata.repository])
		sugg := "Please make sure there are some packages in the GitHub Repository."
		msg := ""
	}
	
	default_pkg_list = []
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		pkg_list = [pkg.name | pkg := response.body.sbom.packages[_]
								pkg.name != response.body.sbom.name
								not startswith(pkg.name, "actions:")]
	
		count(pkg_list) == 0
		msg := sprintf("The GitHub repository %v/%v lacks the necessary configuration files for package managers.", [input.metadata.owner, input.metadata.repository])
		sugg := sprintf("Adhere to the company policy and consider adding the necessary package manager configuration files to the GitHub repository %v/%v.", [input.metadata.owner, input.metadata.repository])
		error := ""
	}`,
	67: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	123: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	131: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	176: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	204: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	18: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	58: `
	package opsmx

	deny[msg] {
		# spec.securityContext.fsGroup field is immutable.
		not is_update(input.request)

		spec := input.request.object.spec
		not input_fsGroup_allowed(spec)
		msg := sprintf("The provided pod spec fsGroup is not allowed, pod: %v. Allowed fsGroup: %v", [input.request.object.metadata.name, input.parameters])
	}

	input_fsGroup_allowed(_) {
		# RunAsAny - No range is required. Allows any fsGroup ID to be specified.
		input.parameters.rule == "RunAsAny"
	}
	input_fsGroup_allowed(spec) {
		# MustRunAs - Validates pod spec fsgroup against all ranges
		input.parameters.rule == "MustRunAs"
		fg := spec.securityContext.fsGroup
		count(input.parameters.ranges) > 0
		range := input.parameters.ranges[_]
		value_within_range(range, fg)
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		not has_field(spec, "securityContext")
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		not spec.securityContext.fsGroup
	}
	input_fsGroup_allowed(spec) {
		# MayRunAs - Validates pod spec fsgroup against all ranges or allow pod spec fsgroup to be left unset
		input.parameters.rule == "MayRunAs"
		fg := spec.securityContext.fsGroup
		count(input.parameters.ranges) > 0
		range := input.parameters.ranges[_]
		value_within_range(range, fg)
	}
	value_within_range(range, value) {
		range.min <= value
		range.max >= value
	}
	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}

	  is_update(request) {
		  request.operation == "UPDATE"
	  }`,
	77: `
	package opsmx
	import future.keywords.in
	
	deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
	  policy = input.conditions[0].condition_name																																																																	

	  input.metadata.results[i].control_title == policy
	  control_struct = input.metadata.results[i]
	  failed_resources = control_struct.failed_resources
	  counter = count(failed_resources)
	  counter > 0
	  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
	  error := ""
	  suggestion := input.metadata.suggestion
	}`,
	277: `
	package opsmx

	default secrets_count = 0
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.owner, input.metadata.repository, input.metadata.build_id, "codeScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	low_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "LOW"]
	secrets_count = count(low_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for %v/%v Github repository for branch %v.\nBelow are the secrets identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, concat(",\n", low_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	226: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	228: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	272: `
	package opsmx

	import data.strings
	default signed_imge_sha = ""
	
	body := {
		"image": input.metadata.image,
			"imageTag": input.metadata.image_tag,
			"username": input.metadata.ssd_secret.docker.username,
			"password": input.metadata.ssd_secret.docker.password
	}
	
	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/artifactSign"])
	
	request = {
		"method": "POST",
		"url": request_url,
		"body": body
	}
	
	response = http.send(request) 
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		response.body.code == 500
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := ""
		error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		response.status_code == 200
		signed_image_sha = response.body.imageSha
		signed_image_sha != input.metadata.image_sha
		msg := "Artifact SHA deployed in Cloud does not match with Signed Artifact SHA."
		sugg :="Kindly check the artifact deployed in cloud."
		error := ""
	}`,
	199: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	293: ``,
	130: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	149: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	161: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	281: `
	package opsmx

	default secrets_count = 0
	
	default image_name = ""
	
	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.image_sha, "imageScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	low_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "LOW"]
	secrets_count = count(low_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for Artifact %v:%v.\nBelow are the secrets identified:\n %v", [image_name, input.metadata.image_tag, concat(",\n", low_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	43: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	236: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	258: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
}`,
	153: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	237: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	256: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	78: `
	package opsmx
	import future.keywords.in
	
	deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
	  policy = input.conditions[0].condition_name
	  
	  input.metadata.results[i].control_title == policy
	  control_struct = input.metadata.results[i]
	  failed_resources = control_struct.failed_resources
	  counter = count(failed_resources)
	  counter > 0
	  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",\n",failed_resources)])
	  error := ""
	  suggestion := input.metadata.suggestion
	}`,
	94: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	114: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	106: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	160: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	240: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	197: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	287: `
	package opsmx
	import future.keywords.in

	default allow = false
	default number_of_merges = 0
	default merges_unreviewed = []
	default merges_reviewed_by_bots = []
	default merges_reviewed_by_author = []

	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/merge_requests?state=merged&order_by=created_at"])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}

	number_of_merges = count(response.body)
	merges_unreviewed = [response.body[i].iid | count(response.body[i].reviewers) == 0]
	merges_reviewed_by_bots = [response.body[i].iid | contains(response.body[i].reviewers[j].username, "bot")]
	merges_reviewed_by_author = [response.body[i].iid | response.body[i].reviewers[j].username == response.body[i].author.username]

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
	count(merges_reviewed_by_bots) > 0
	msg := sprintf("Merge Request with bot user as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_bots])
	sugg := "Adhere to security standards by restricting reviews by bot users."
	error := ""
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
	count(merges_reviewed_by_author) > 0
	msg := sprintf("Merge Request with Author as reviewer found. Merge Request ID: %v.",[merges_reviewed_by_author])
	sugg := "Adhere to security standards by restricting reviews by authors."
	error := ""
	}

	deny[{"alertMsg": msg, "error": error, "suggestion": sugg}]{
	count(merges_unreviewed) > 0
	msg := sprintf("Unreviewed Merge Requests found to be merged. Merge Request ID: %v.",[merges_unreviewed])
	sugg := "Adhere to security standards by restricting merges without reviews."
	error := ""
	}`,
	33: `
	package opsmx
	import future.keywords.in
	
	request_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=admin"])
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository collaborators."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	default denial_list = false
	
	denial_list = matched_users
	
	matched_users[user] {
		users := [response.body[i].login | response.body[i].type == "User"]
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
	  counter := count(denial_list)
	  counter > 0
	  denial_list_str := concat(", ", denial_list)
	  msg := sprintf("Owner access of Github Repository is granted to bot users. Number of bot users having owner access: %v. Name of bots having owner access: %v", [counter, denial_list_str])
	  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	  error := ""
	}`,
	63: `
	package opsmx

	deny[msg] {
		not is_update(input.request)

		c := input_containers[_]
		allowedProcMount := get_allowed_proc_mount(input)
		not input_proc_mount_type_allowed(allowedProcMount, c)
		msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
	}

	input_proc_mount_type_allowed(allowedProcMount, c) {
		allowedProcMount == "default"
		lower(c.securityContext.procMount) == "default"
	}
	input_proc_mount_type_allowed(allowedProcMount, _) {
		allowedProcMount == "unmasked"
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
		c.securityContext.procMount
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
		c.securityContext.procMount
	}

	get_allowed_proc_mount(arg) = out {
		not arg.parameters
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		not arg.parameters.procMount
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		arg.parameters.procMount
		not valid_proc_mount(arg.parameters.procMount)
		out = "default"
	}
	get_allowed_proc_mount(arg) = out {
		valid_proc_mount(arg.parameters.procMount)
		out = lower(arg.parameters.procMount)
	}

	valid_proc_mount(str) {
		lower(str) == "default"
	}
	valid_proc_mount(str) {
		lower(str) == "unmasked"
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	179: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	213: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	262: `
	package opsmx
	input_stages = input.metadata.stages
	manualJudgment_stages = [input.metadata.stages[i] | input.metadata.stages[i].type == "manualJudgment"]
	counter = count(manualJudgment_stages)
	deny["No manual judgement stages configured in pipeline"]{
  	count(manualJudgment_stages) < 1
	}`,
	66: `
	package opsmx
	import future.keywords.in
	
	request_url_p1 = concat("/",[input.metadata.ssd_secret.sonarQube_creds.url,"api/qualitygates/project_status?projectKey"])
	request_url = concat("=", [request_url_p1, input.metadata.sonarqube_projectKey])
	
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	
	default response = ""
	response = http.send(request)
	
	eny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable."
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.projectStatus.status == "ERROR"
	  msg := sprintf("SonarQube Quality Gate Status Check has failed for project %s. Prioritize and address the identified issues promptly to meet the defined quality standards and ensure software reliability.", [input.metadata.sonarqube_projectKey])
	  error := ""
	  sugg := "Prioritize and address the identified issues promptly to meet the defined quality standards and ensure software reliability."
	}`,
	104: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	142: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	80: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	90: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	96: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	116: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	203: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	25: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	35: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	default active_hooks = []
	default active_hooks_count = 0
	default hooks_with_secret = []
	default hooks_with_secret_count = 0
	
	request_url = concat("/",[input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	active_hooks = [response.body[i].config | response.body[i].active == true]
	hooks_with_secret = [response.body[i].config.secret | response.body[i].active == true]
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository webhook configuration due to Bad Credentials."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
	  error := "Mentioned branch for Repository not found while trying to fetch repository webhook configuration. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	active_hooks_count = count(active_hooks)
	hooks_with_secret_count = count(hooks_with_secret)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  active_hooks_count != 0
	
	  active_hooks_count > hooks_with_secret_count
	  msg := sprintf("Webhook authentication failed: Secret not set for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by configuring the webhook secret for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  error := ""  
	}`,
	62: `
	package opsmx

	deny[msg] {
		not is_update(input.request)

		c := input_containers[_]
		c.securityContext.privileged
		msg := sprintf("Privileged container is not allowed: %v, securityContext: %v", [c.name, c.securityContext])
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	224: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	127: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	136: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	206: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	31: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	41: `
	package opsmx
	import future.keywords.in

	default approved_artifact_repos = []
	default image_source = ""

	image_details = split(input.metadata.image,"/")

	image_source = concat("/",["docker.io", image_details[0]]) {
	count(image_details) <= 2
	not contains(image_details[0], ".")
	}

	image_source = concat("/",[image_details[0], image_details[1]]) {
	count(image_details) == 2
	contains(image_details[0], ".")
	}

	image_source = concat("/",[image_details[0], image_details[1]]) {
	count(image_details) == 3
	}

	approved_artifact_repos = split(input.metadata.ssd_secret.authorized_artifact_repo, ",")

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	count(approved_artifact_repos) == 0
	error := "The essential list of Authorized Artifact Repositories remains unspecified."
	sugg := "Set the AuthorizedArtifactRepos parameter with trusted Artifact Repo to strengthen artifact validation during the deployment process."
	msg := ""
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	not image_source in approved_artifact_repos

	msg := sprintf("The artifact %v:%v has not been sourced from an authorized artifact repo.\nPlease verify the artifacts origin against the following Authorized Artifact Repositories: %v", [input.metadata.image, input.metadata.image_tag, input.metadata.ssd_secret.authorized_artifact_repo])
	sugg := "Ensure the artifact is sourced from an authorized artifact repo."
	error := ""
	}`,
	113: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	73: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	196: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	222: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	120: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	205: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	218: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	198: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	216: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	233: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	242: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	3: `
	package opsmx

	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.github_org, input.metadata.github_repo,"branches",input.metadata.branch,"protection"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	raw_body = response.raw_body
	parsed_body = json.unmarshal(raw_body)
	obj := response.body
	has_key(x, k) {
	   dont_care(x[k])
	}
	dont_care(_) = true
	default branch_protection = false
	branch_protection = has_key(obj, "required_pull_request_reviews")
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 404
	  msg := ""
	  sugg := "Kindly provide the accurate repository name, organization, and branch details"
	  error := sprintf("%v %v",[response.status_code,response.body.message])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 403
	  msg := ""
	  sugg := sprintf("The repository %v is private,Make this repository public to enable this feature", [input.metadata.github_repo])
	  error := sprintf("%v %v",[response.status_code,response.body.message])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 401
	  msg := ""
	  sugg := "Please provide the Appropriate Git Token for the User"
	  error := sprintf("%s %v", [parsed_body.message,response.status])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code = 500
	  msg := "Internal Server Error"
	  sugg := ""
	  error := "GitHub is not reachable"
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  branch_protection != true
	  msg := sprintf("Github repo %v of branch %v is not protected", [input.metadata.github_repo, input.metadata.default_branch])
	  sugg := sprintf("Adhere to the company policy by enforcing Code Owner Reviews for %s Github repo",[input.metadata.github_repo])
	  error := ""
	}`,
	50: `
	package opsmx

	missing(obj, field) = true {
	  not obj[field]
	}
	
	missing(obj, field) = true {
	  obj[field] == ""
	}
	
	canonify_cpu(orig) = new {
	  is_number(orig)
	  new := orig * 1000
	}
	
	canonify_cpu(orig) = new {
	  not is_number(orig)
	  endswith(orig, "m")
	  new := to_number(replace(orig, "m", ""))
	}
	
	canonify_cpu(orig) = new {
	  not is_number(orig)
	  not endswith(orig, "m")
	  regex.find_n("^[0-9]+$", orig, -1)
	  new := to_number(orig) * 1000
	}
	
	canonify_cpu(orig) = new {
	  not is_number(orig)
	  not endswith(orig, "m")
	  regex.find_n("^[0-9]+[.][0-9]+$", orig, -1)
	  new := to_number(orig) * 1000
	}
	
	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000 { true }
	
	# 10 ** 18
	mem_multiple("P") = 1000000000000000000 { true }
	
	# 10 ** 15
	mem_multiple("T") = 1000000000000000 { true }
	
	# 10 ** 12
	mem_multiple("G") = 1000000000000 { true }
	
	# 10 ** 9
	mem_multiple("M") = 1000000000 { true }
	
	# 10 ** 6
	mem_multiple("k") = 1000000 { true }
	
	# 10 ** 3
	mem_multiple("") = 1000 { true }
	
	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741
	# 10 ** 0
	mem_multiple("m") = 1 { true }
	
	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000 { true }
	
	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000 { true }
	
	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000 { true }
	
	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000 { true }
	
	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000 { true }
	
	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000 { true }
	
	get_suffix(mem) = suffix {
	  not is_string(mem)
	  suffix := ""
	}
	
	get_suffix(mem) = suffix {
	  is_string(mem)
	  count(mem) > 0
	  suffix := substring(mem, count(mem) - 1, -1)
	  mem_multiple(suffix)
	}
	
	get_suffix(mem) = suffix {
	  is_string(mem)
	  count(mem) > 1
	  suffix := substring(mem, count(mem) - 2, -1)
	  mem_multiple(suffix)
	}
	
	get_suffix(mem) = suffix {
	  is_string(mem)
	  count(mem) > 1
	  not mem_multiple(substring(mem, count(mem) - 1, -1))
	  not mem_multiple(substring(mem, count(mem) - 2, -1))
	  suffix := ""
	}
	
	get_suffix(mem) = suffix {
	  is_string(mem)
	  count(mem) == 1
	  not mem_multiple(substring(mem, count(mem) - 1, -1))
	  suffix := ""
	}
	
	get_suffix(mem) = suffix {
	  is_string(mem)
	  count(mem) == 0
	  suffix := ""
	}
	
	canonify_mem(orig) = new {
	  is_number(orig)
	  new := orig * 1000
	}
	
	canonify_mem(orig) = new {
	  not is_number(orig)
	  suffix := get_suffix(orig)
	  raw := replace(orig, suffix, "")
	  regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
	  new := to_number(raw) * mem_multiple(suffix)
	}
	
	deny[msg] {
	  general_violation[{"msg": msg, "field": "containers"}]
	}
	
	deny[msg] {
	  general_violation[{"msg": msg, "field": "initContainers"}]
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  cpu_orig := container.resources.limits.cpu
	  not canonify_cpu(cpu_orig)
	  msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  mem_orig := container.resources.limits.memory
	  not canonify_mem(mem_orig)
	  msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  cpu_orig := container.resources.requests.cpu
	  not canonify_cpu(cpu_orig)
	  msg := sprintf("container <%v> cpu request <%v> could not be parsed", [container.name, cpu_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  mem_orig := container.resources.requests.memory
	  not canonify_mem(mem_orig)
	  msg := sprintf("container <%v> memory request <%v> could not be parsed", [container.name, mem_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  not container.resources
	  msg := sprintf("container <%v> has no resource limits", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  not container.resources.limits
	  msg := sprintf("container <%v> has no resource limits", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  missing(container.resources.limits, "cpu")
	  msg := sprintf("container <%v> has no cpu limit", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  missing(container.resources.limits, "memory")
	  msg := sprintf("container <%v> has no memory limit", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  not container.resources.requests
	  msg := sprintf("container <%v> has no resource requests", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  missing(container.resources.requests, "cpu")
	  msg := sprintf("container <%v> has no cpu request", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  missing(container.resources.requests, "memory")
	  msg := sprintf("container <%v> has no memory request", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  cpu_limits_orig := container.resources.limits.cpu
	  cpu_limits := canonify_cpu(cpu_limits_orig)
	  cpu_requests_orig := container.resources.requests.cpu
	  cpu_requests := canonify_cpu(cpu_requests_orig)
	  cpu_ratio := object.get(input.parameters, "cpuRatio", input.parameters.ratio)
	  to_number(cpu_limits) > to_number(cpu_ratio) * to_number(cpu_requests)
	  msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, cpu_limits_orig, cpu_ratio])
	}
	
	general_violation[{"msg": msg, "field": field}] {
	  container := input.request.object.spec[field][_]
	  mem_limits_orig := container.resources.limits.memory
	  mem_requests_orig := container.resources.requests.memory
	  mem_limits := canonify_mem(mem_limits_orig)
	  mem_requests := canonify_mem(mem_requests_orig)
	  mem_ratio := input.parameters.ratio
	  to_number(mem_limits) > to_number(mem_ratio) * to_number(mem_requests)
	  msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed ratio of <%v>", [container.name, mem_limits_orig, mem_ratio])
	}`,
	139: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	5: `
	package opsmx
import future.keywords.in

default allow = false

request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "branches", input.metadata.branch, "protection", "required_signatures"]
request_url = concat("/",request_components)

token = input.metadata.ssd_secret.github.token
request = {
    "method": "GET",
    "url": request_url,
    "headers": {
        "Authorization": sprintf("Bearer %v", [token]),
    },
}

response = http.send(request)

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code == 401
  error := "Unauthorized to check repository branch configuration due to Bad Credentials."
  msg := ""
  sugg := "Kindly check the access token. It must have enough permissions to get repository branch configurations."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 404
  error := "The branch protection policy for mentioned branch for Repository not found while trying to fetch repository branch configuration."
  sugg := "Kindly check if the repository and branch provided is correct and the access token has rights to read repository branch protection policy configuration. Also check if the branch protection policy is configured for this repository."
  msg := ""
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
  response.status_code == 500
  msg := "Internal Server Error."
  sugg := ""
  error := "GitHub is not reachable."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  codes = [401, 404, 500, 200, 302]
  not response.status_code in codes
  msg := ""
  error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch configuration.", [response.status_code, response.body.message])
  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
}

deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
  response.status_code in [200, 302]
  response.body.enabled != true
  msg := sprintf("Branch %v of Github Repository %v/%v does not have signed commits mandatory.", [input.metadata.branch, input.metadata.owner, input.metadata.repository])
  error := ""
  sugg := sprintf("Adhere to the company policy by enforcing all commits to be signed for %v/%v Github repo", [input.metadata.owner, input.metadata.repository])
}`,
	158: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	260: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := sprintf("Implement best practices as mentioned in %v to improve overall compliance score.", [input.metadata.references])
}`,
	9: `
package opsmx
severities = ["MODERATE","UNDEFINED","MEDIUM"]
vuln_id = input.conditions[0].condition_value
vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
deny[msg]{
some i
inputSeverity = severities[i]
some j
vuln_severity[j] == inputSeverity 
msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
} `,
	15: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	249: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	20: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	125: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	230: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	239: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	280: `
	package opsmx

	default secrets_count = 0
	
	default image_name = ""
	
	image_name = input.metadata.image {
		not contains(input.metadata.image,"/")
	}
	image_name = split(input.metadata.image,"/")[1] {
		contains(input.metadata.image,"/")
	}
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.image_sha, "imageScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	medium_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "MEDIUM"]
	secrets_count = count(medium_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for Artifact %v:%v.\nBelow are the secrets identified:\n %v", [image_name, input.metadata.image_tag, concat(",\n", medium_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	51: ``,
	85: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	163: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	121: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	261: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	default auto_merge_config = ""
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	auto_merge_config = response.body.allow_auto_merge
	status_code = response.status_code
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check the Branch Protection Policy"
	  error := "401 Unauthorized"
	  sugg := "Kindly check the access token. It must have enough permissions to read the branch protection policy for repository."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 200, 301, 302]
	  not response.status_code in codes
	  msg = "Unable to fetch Branch Protection Policy"
	  error = sprintf("Error %v:%v receieved from Github upon trying to fetch Branch Protection Policy.", [status_code, response.body.message])
	  sugg = "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  status_code in [200, 301, 302]
	  auto_merge_config == ""
	  msg = "Auto Merge Config Not Found, indicates Branch Protection Policy is not set"
	  error = ""
	  sugg = "Kindly configure Branch Protection Policy for source code repository and make sure to restrict auto merge."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  status_code in [200, 301, 302]
	  auto_merge_config != input.conditions[0].condition_value
	  msg = sprintf("Auto Merge is allowed in repo %v", [input.metadata.repository])
	  error = ""
	  sugg = "Kindly restrict auto merge in Branch Protection Policy applied to repository."  
	}`,
	1: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	default private_repo = ""
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	raw_body = response.raw_body
	parsed_body = json.unmarshal(raw_body)
	private_repo = response.body.private
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check repository configuration due to Bad Credentials."
	  error := "401 Unauthorized."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := "Repository not found while trying to fetch Repository Configuration."
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
	  error := "Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := "Unable to fetch repository configuration."
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  private_repo = false
	  msg := sprintf("Repository %v/%v is publically accessible.", [input.metadata.owner,input.metadata.repository])
	  sugg := "Please change the repository visibility to private."
	  error := ""
	}`,
	59: `
	package opsmx

	deny[msg] {
		not is_update(input.request)
		volume := input_hostpath_volumes[_]
		allowedPaths := get_allowed_paths(input)
		input_hostpath_violation(allowedPaths, volume)
		msg := sprintf("HostPath volume %v is not allowed, pod: %v. Allowed path: %v", [volume, input.request.object.metadata.name, allowedPaths])
	}

	input_hostpath_violation(allowedPaths, _) {
		allowedPaths == []
	}
	input_hostpath_violation(allowedPaths, volume) {
		not input_hostpath_allowed(allowedPaths, volume)
	}

	get_allowed_paths(arg) = out {
		not arg.parameters
		out = []
	}
	get_allowed_paths(arg) = out {
		not arg.parameters.allowedHostPaths
		out = []
	}
	get_allowed_paths(arg) = out {
		out = arg.parameters.allowedHostPaths
	}

	input_hostpath_allowed(allowedPaths, volume) {
		allowedHostPath := allowedPaths[_]
		path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
		not allowedHostPath.readOnly == true
	}

	input_hostpath_allowed(allowedPaths, volume) {
		allowedHostPath := allowedPaths[_]
		path_matches(allowedHostPath.pathPrefix, volume.hostPath.path)
		allowedHostPath.readOnly
		not writeable_input_volume_mounts(volume.name)
	}

	writeable_input_volume_mounts(volume_name) {
		container := input_containers[_]
		mount := container.volumeMounts[_]
		mount.name == volume_name
		not mount.readOnly
	}

	# This allows "/foo", "/foo/", "/foo/bar" etc., but
	# disallows "/fool", "/etc/foo" etc.
	path_matches(prefix, path) {
		a := path_array(prefix)
		b := path_array(path)
		prefix_matches(a, b)
	}
	path_array(p) = out {
		p != "/"
		out := split(trim(p, "/"), "/")
	}
	# This handles the special case for "/", since
	# split(trim("/", "/"), "/") == [""]
	path_array("/") = []

	prefix_matches(a, b) {
		count(a) <= count(b)
		not any_not_equal_upto(a, b, count(a))
	}

	any_not_equal_upto(a, b, n) {
		a[i] != b[i]
		i < n
	}

	input_hostpath_volumes[v] {
		v := input.request.object.spec.volumes[_]
		has_field(v, "hostPath")
	}

	# has_field returns whether an object has a field
	has_field(object, field) = true {
		object[field]
	}
	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	84: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	135: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	38: `
	package opsmx


deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.build_image_sha == "" 
    msg = ""
    sugg = "Ensure that build platform is integrated with SSD."
    error = "Complete Build Artifact information could not be identified."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.image_sha == ""
    msg = ""
    sugg = "Ensure that deployment platform is integrated with SSD usin Admission Controller."
    error = "Artifact information could not be identified from Deployment Environment."
}

deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
    input.metadata.image_sha != input.metadata.build_image_sha
    
    msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
    sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
    error = ""
}`,
	39: `
	package opsmx


	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.build_image_sha == "" 
		msg = ""
		sugg = "Ensure that build platform is integrated with SSD."
		error = "Complete Build Artifact information could not be identified."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.image_sha == ""
		msg = ""
		sugg = "Ensure that deployment platform is integrated with SSD usin Admission Controller."
		error = "Artifact information could not be identified from Deployment Environment."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		input.metadata.image_sha != input.metadata.build_image_sha
		
		msg = sprintf("Non-identical by hash artifacts identified at Build stage and Deployment Environment.\nBuild Image: %v:%v \n Deployed Image: %v:%v", [input.metadata.build_image, input.metadata.build_image_tag, input.metadata.image, input.metadata.image_tag])
		sugg = "Ensure that built image details & deployed Image details match. Check for possible misconfigurations."
		error = ""
	}`,
	126: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	7: `
package opsmx
severities = ["LOW"]
vuln_id = input.conditions[0].condition_value
vuln_severity = {input.conditions[i].condition_value | input.conditions[i].condition_name = "severity"}
deny[msg]{
some i
inputSeverity = severities[i]
some j
vuln_severity[j] == inputSeverity
msg:= sprintf("%v Criticality Vulnerability : %v found in component: %v", [inputSeverity, vuln_id, input.metadata.package_name])
}`,
	212: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	267: `
	package opsmx
	import future.keywords.in

	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "collaborators"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository collaborators."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  admins = [response.body[i].login | response.body[i].role_name == "admin"]
	  total_users = count(response.body[i])
	  admin_users = count(admins)
	  admin_percentage = admin_users / total_users * 100
	
	  admin_percentage > 5
	  msg := sprintf("More than 5 percentage of total collaborators of %v github repository have admin access", [input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy and revoke admin access to some users of the repo %v", [input.metadata.repository])
	  error := ""
	}`,
	210: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	112: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	157: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	186: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	207: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	221: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	253: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	70: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	93: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	150: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	32: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	outside_collaborators_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?affiliation=outside&per_page=100"])
	
	request = {
		"method": "GET",
		"url": outside_collaborators_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}
	
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository collaborators."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 301, 302]
	  count(response.body) > 0
	
	  collaborators_list = concat(",\n", [response.body[i].login | response.body[i].type == "User"]) 
	  msg := sprintf("%v outside collaborators have access to repository. \n The list of outside collaborators is: %v.", [response.body, count(collaborators_list)])
	  sugg := "Adhere to the company policy by revoking the access of non-organization members for Github repo."
	  error := ""
	}`,
	119: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	132: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	124: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	241: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	252: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	274: `
	package opsmx

	default secrets_count = 0
	
	request_url = concat("/",[input.metadata.toolchain_addr,"api", "v1", "scanResult?fileName="])
	filename_components = [input.metadata.owner, input.metadata.repository, input.metadata.build_id, "codeScanResult.json"]
	filename = concat("_", filename_components)
	
	complete_url = concat("", [request_url, filename])
	
	request = {
		"method": "GET",
		"url": complete_url
	}
	
	response = http.send(request)
	
	high_severity_secrets = [response.body.Results[0].Secrets[i].Title | response.body.Results[0].Secrets[i].Severity == "HIGH"]
	secrets_count = count(high_severity_secrets)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  secrets_count > 0
	
	  msg := sprintf("Secret found for %v/%v Github repository for branch %v.\nBelow are the secrets identified:\n %s", [input.metadata.owner, input.metadata.repository, input.metadata.branch, concat(",\n", high_severity_secrets)])
	  sugg := "Eliminate the aforementioned sensitive information to safeguard confidential data."
	  error := ""
	}`,
	294: ``,
	52: `
	package opsmx

        severity = "low"
        default findings_count = 0

        complete_url = concat("",[input.metadata.toolchain_addr,"api/v1/scanResult?fileName=findings_", input.metadata.owner, "_", input.metadata.repository, "_", severity, "_", input.metadata.build_id, "_semgrep.json"]	)
        request = {	
                "method": "GET",
                "url": complete_url
        }

        response = http.send(request)

        findings_count = response.body.totalFindings

        deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
          findings_count > 0
          msg := sprintf("The github repository %v/%v contains %v findings of %v severity.", [input.metadata.owner, input.metadata.repository, findings_count, severity])
          sugg := "Please examine the medium-severity findings in the SEMGREP analysis data, available through the View Findings button and proactively review your code for common issues and apply best coding practices during development to prevent such alerts from arising."
          error := ""
        }`,
	55: `
	package opsmx

	deny[msg] {
	# spec.containers.securityContext.capabilities field is immutable.
	not is_update(input.request)

	container := input.request.object.spec.containers[_]
	has_disallowed_capabilities(container)
	msg := sprintf("container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
	}

	deny[msg] {
	not is_update(input.request)
	container := input.request.object.spec.containers[_]
	missing_drop_capabilities(container)
	msg := sprintf("container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
	}

	deny[msg] {
	not is_update(input.request)
	container := input.request.object.spec.initContainers[_]
	has_disallowed_capabilities(container)
	msg := sprintf("init container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
	}

	deny[msg] {
	not is_update(input.request)
	container := input.request.object.spec.initContainers[_]
	missing_drop_capabilities(container)
	msg := sprintf("init container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
	}

	deny[msg] {
	not is_update(input.request)
	container := input.request.object.spec.ephemeralContainers[_]
	has_disallowed_capabilities(container)
	msg := sprintf("ephemeral container <%v> has a disallowed capability. Allowed capabilities are %v", [container.name, get_default(input.parameters, "allowedCapabilities", "NONE")])
	}

	deny[msg] {
	not is_update(input.request)
	container := input.request.object.spec.ephemeralContainers[_]
	missing_drop_capabilities(container)
	msg := sprintf("ephemeral container <%v> is not dropping all required capabilities. Container must drop all of %v or \"ALL\"", [container.name, input.parameters.requiredDropCapabilities])
	}


	has_disallowed_capabilities(container) {
	allowed := {c | c := lower(input.parameters.allowedCapabilities[_])}
	not allowed["*"]
	capabilities := {c | c := lower(container.securityContext.capabilities.add[_])}

	count(capabilities - allowed) > 0
	}

	missing_drop_capabilities(container) {
	must_drop := {c | c := lower(input.parameters.requiredDropCapabilities[_])}
	all := {"all"}
	dropped := {c | c := lower(container.securityContext.capabilities.drop[_])}

	count(must_drop - dropped) > 0
	count(all - dropped) > 0
	}

	get_default(obj, param, _) = out {
	out = obj[param]
	}

	get_default(obj, param, _default) = out {
	not obj[param]
	not obj[param] == false
	out = _default
	}

	is_update(review) {
		review.operation == "UPDATE"
	}`,
	97: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	23: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	171: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	141: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",
,failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	202: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	61: `
	package opsmx

	deny[msg] {
		not is_update(input.request)

		input_share_hostnetwork(input.request.object)
		msg := sprintf("The specified hostNetwork and hostPort are not allowed, pod: %v. Allowed values: %v", [input.request.object.metadata.name, input.parameters])
	}

	input_share_hostnetwork(o) {
		not input.parameters.hostNetwork
		o.spec.hostNetwork
	}

	input_share_hostnetwork(_) {
		hostPort := input_containers[_].ports[_].hostPort
		hostPort < input.parameters.min
	}

	input_share_hostnetwork(_) {
		hostPort := input_containers[_].ports[_].hostPort
		hostPort > input.parameters.max
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}

	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	is_update(request) {
		request.operation == "UPDATE"
	}`,
	91: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	266: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	maintainers_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=maintain&per_page=100"])
	admins_url = concat("/", [input.metadata.ssd_secret.github.rest_api_url, "repos", input.metadata.owner, input.metadata.repository, "collaborators?permission=admin&per_page=100"])
	
	maintainers_request = {
		"method": "GET",
		"url": maintainers_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}
	
	default maintainers_response = ""
	maintainers_response = http.send(maintainers_request)
	maintainers = [maintainers_response.body[i].login | maintainers_response.body[i].type == "User"]
	
	admins_request = {
		"method": "GET",
		"url": admins_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.github.token]),
		},
	}
	
	default admins_response = ""
	admins_response = http.send(admins_request)
	
	admins = [admins_response.body[i].login | admins_response.body[i].type == "User"]
	non_admin_maintainers = [maintainers[idx] | not maintainers[idx] in admins]
	complete_list = array.concat(admins, non_admin_maintainers)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  maintainers_response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository collaborators."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  admins_response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository collaborators."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository collaborators."
	}
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  maintainers_response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  admins_response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository collaborators."
	  error := "Mentioned branch for Repository not found while trying to fetch repository collaborators. Repo name or Organisation is incorrect."
	}
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  admins_response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  maintainers_response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not admins_response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [admins_response.status_code, admins_response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not maintainers_response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository collaborators. Error %v:%v receieved from Github.", [maintainers_response.status_code, maintainers_response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	default denial_list = false
	
	denial_list = matched_users
	
	matched_users[user] {
		users := complete_list
		user := users[_]
		patterns := ["bot", "auto", "test", "jenkins", "drone", "github", "gitlab", "aws", "azure"]
		some pattern in patterns
			regex.match(pattern, user)
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}] {
	  counter := count(denial_list)
	  counter > 0
	  denial_list_str := concat(", ", denial_list)
	  msg := sprintf("Maintainer and Admin access of Github Repository providing ability to merge code is granted to bot users. Number of bot users having permissions to merge: %v. Name of bots having permissions to merge: %v", [counter, denial_list_str])
	  sugg := sprintf("Adhere to the company policy and revoke access of bot user for %v/%v Repository.", [input.metadata.repository,input.metadata.owner])
	  error := ""
	}`,
	54: `
	package opsmx

	deny[msg] {
		metadata := input.request.object.metadata
		container := input_containers[_]
		not input_apparmor_allowed(container, metadata)
		msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.request.object.metadata.name, container.name, input.parameters.allowedProfiles])
	}

	input_apparmor_allowed(container, metadata) {
		get_annotation_for(container, metadata) == input.parameters.allowedProfiles[_]
	}

	input_containers[c] {
		c := input.request.object.spec.containers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.initContainers[_]
	}
	input_containers[c] {
		c := input.request.object.spec.ephemeralContainers[_]
	}

	get_annotation_for(container, metadata) = out {
		out = metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
	}
	get_annotation_for(container, metadata) = out {
		not metadata.annotations[sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])]
		out = "runtime/default"
	}`,
	162: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	189: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	2: `
	package opsmx
	import future.keywords.in		
	
	default allow = false
	
	required_min_reviewers = {input.conditions[i].condition_value|input.conditions[i].condition_name == "Minimum Reviewers Policy"}
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository,"branches",input.metadata.branch, "protection"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	raw_body = response.raw_body
	parsed_body = json.unmarshal(raw_body)
	reviewers = response.body.required_pull_request_reviews.required_approving_review_count
	
	allow {
	  response.status_code = 200
	}
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	  msg := ""
	  sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  error := "The branch protection policy for mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	  msg := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  not response.status_code in [401, 404, 500, 200, 301, 302]
	  msg := ""
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch repository branch protection policy configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  reviewers == 0
	  msg := sprintf("The branch protection policy that mandates a pull request before merging has been deactivated for the %s branch of the %v on GitHub", [input.metadata.branch,input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s Github repo", [input.metadata.repository])
	  error := ""
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  reviewers < required_min_reviewers
	  msg := sprintf("The branch protection policy that mandates a pull request before merging has mandatory reviewers count less than required for the %s branch of the %v on GitHub", [input.metadata.branch,input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by establishing the correct minimum reviewers for %s Github repo", [input.metadata.repository])
	  error := ""
	}`,
	22: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	36: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	default active_hooks = []
	default active_hooks_count = 0
	default insecure_active_hooks = []
	default insecure_active_hooks_count = 0
	
	request_url = concat("/",[input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository, "hooks"])
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	active_hooks = [response.body[i].config | response.body[i].active == true]
	insecure_active_hooks = [active_hooks[j].url | active_hooks[j].insecure_ssl == "1"]
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := ""
	  error := "401 Unauthorized: Unauthorized to check repository webhook configuration due to Bad Credentials."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository webhook configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository webhook configuration."
	  error := "Mentioned branch for Repository not found while trying to fetch repository webhook configuration. Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Unable to fetch repository webhook configuration. Error %v:%v receieved from Github upon trying to fetch repository webhook configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	active_hooks_count = count(active_hooks)
	insecure_active_hooks_count = count(insecure_active_hooks)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  active_hooks_count > 0
	  insecure_active_hooks_count > 0
	
	  msg := sprintf("Webhook SSL Check failed: SSL/TLS not enabled for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by enabling the webhook ssl/tls for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  error := ""  
	}`,
	201: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	46: `
	package opsmx

	missing(obj, field) {
		not obj[field]
	}
	
	missing(obj, field) {
		obj[field] == ""
	}
	
	canonify_cpu(orig) = new {
		is_number(orig)
		new := orig * 1000
	}
	
	canonify_cpu(orig) = new {
		not is_number(orig)
		endswith(orig, "m")
		new := to_number(replace(orig, "m", ""))
	}
	
	canonify_cpu(orig) = new {
		not is_number(orig)
		not endswith(orig, "m")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", orig,-1)
		new := to_number(orig) * 1000
	}
	
	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000
	
	# 10 ** 18
	mem_multiple("P") = 1000000000000000000
	
	# 10 ** 15
	mem_multiple("T") = 1000000000000000
	
	# 10 ** 12
	mem_multiple("G") = 1000000000000
	
	# 10 ** 9
	mem_multiple("M") = 1000000000
	
	# 10 ** 6
	mem_multiple("k") = 1000000
	
	# 10 ** 3
	mem_multiple("") = 1000
	
	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741
	
	# 10 ** 0
	mem_multiple("m") = 1
	
	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000
	
	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000
	
	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000
	
	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000
	
	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000
	
	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000
	
	get_suffix(mem) = suffix {
		not is_string(mem)
		suffix := ""
	}
	
	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 0
		suffix := substring(mem, count(mem) - 1, -1)
		mem_multiple(suffix)
	}
	
	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		suffix := substring(mem, count(mem) - 2, -1)
		mem_multiple(suffix)
	}
	
	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) > 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		not mem_multiple(substring(mem, count(mem) - 2, -1))
		suffix := ""
	}
	
	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 1
		not mem_multiple(substring(mem, count(mem) - 1, -1))
		suffix := ""
	}
	
	get_suffix(mem) = suffix {
		is_string(mem)
		count(mem) == 0
		suffix := ""
	}
	
	canonify_mem(orig) = new {
		is_number(orig)
		new := orig * 1000
	}
	
	canonify_mem(orig) = new {
		not is_number(orig)
		suffix := get_suffix(orig)
		raw := replace(orig, suffix, "")
		regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
		new := to_number(raw) * mem_multiple(suffix)
	}
	
	# Ephemeral containers not checked as it is not possible to set field.
	
	deny[msg] {
	  general_violation[{"msg": msg, "field": "containers"}]
	}
	
	deny[msg] {
	  general_violation[{"msg": msg, "field": "initContainers"}]
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		not canonify_cpu(cpu_orig)
		msg := sprintf("container <%v> cpu limit <%v> could not be parsed", [container.name, cpu_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		not canonify_mem(mem_orig)
		msg := sprintf("container <%v> memory limit <%v> could not be parsed", [container.name, mem_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		not container.resources.limits
		msg := sprintf("container <%v> has no resource limits", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "cpu")
		msg := sprintf("container <%v> has no cpu limit", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		missing(container.resources.limits, "memory")
		msg := sprintf("container <%v> has no memory limit", [container.name])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		cpu_orig := container.resources.limits.cpu
		cpu := canonify_cpu(cpu_orig)
		max_cpu_orig := input.parameters.cpu
		max_cpu := canonify_cpu(max_cpu_orig)
		cpu > max_cpu
		msg := sprintf("container <%v> cpu limit <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
	}
	
	general_violation[{"msg": msg, "field": field}] {
		container := input.request.object.spec[field][_]
		mem_orig := container.resources.limits.memory
		mem := canonify_mem(mem_orig)
		max_mem_orig := input.parameters.memory
		max_mem := canonify_mem(max_mem_orig)
		mem > max_mem
		msg := sprintf("container <%v> memory limit <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
	}`,
	86: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	183: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	159: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	181: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	182: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	229: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	246: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	27: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	83: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	118: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	285: `
	package opsmx
	default low_severities = []
	
	default multi_alert = false
	default exists_alert = false
	
	exists_alert = check_if_low_alert_exists
	multi_alert = check_if_multi_alert
	
	check_if_low_alert_exists = exists_flag {
	  low_severities_counter = count(input.metadata.results[0].LowSeverity)
	  low_severities_counter > 0
	  exists_flag = true
	}
	
	check_if_multi_alert() = multi_flag {
	  low_severities_counter = count(input.metadata.results[0].LowSeverity)
	  low_severities_counter > 1
	  multi_flag = true
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  check_if_low_alert_exists
	  check_if_multi_alert
	  
	  some i
	  rule = input.metadata.results[0].LowSeverity[i].RuleID
	  title = input.metadata.results[0].LowSeverity[i].Title
	  targets = concat(",\n", input.metadata.results[0].LowSeverity[i].TargetResources)
	  resolution = input.metadata.results[0].LowSeverity[i].Resolution
	  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of low severity:\n %v", [rule, title, targets])
	  sugg := resolution
	  error := ""
	}`,
	98: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	243: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	14: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	28: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	47: `
	package opsmx

	missing(obj, field) = true {
	not obj[field]
	}

	missing(obj, field) = true {
	obj[field] == ""
	}

	canonify_cpu(orig) = new {
	is_number(orig)
	new := orig * 1000
	}

	canonify_cpu(orig) = new {
	not is_number(orig)
	endswith(orig, "m")
	new := to_number(replace(orig, "m", ""))
	}

	canonify_cpu(orig) = new {
	not is_number(orig)
	not endswith(orig, "m")
	regex.find_n("^[0-9]+(\\.[0-9]+)?$", orig, -1)
	new := to_number(orig) * 1000
	}

	# 10 ** 21
	mem_multiple("E") = 1000000000000000000000 { true }

	# 10 ** 18
	mem_multiple("P") = 1000000000000000000 { true }

	# 10 ** 15
	mem_multiple("T") = 1000000000000000 { true }

	# 10 ** 12
	mem_multiple("G") = 1000000000000 { true }

	# 10 ** 9
	mem_multiple("M") = 1000000000 { true }

	# 10 ** 6
	mem_multiple("k") = 1000000 { true }

	# 10 ** 3
	mem_multiple("") = 1000 { true }

	# Kubernetes accepts millibyte precision when it probably shouldnt.
	# https://github.com/kubernetes/kubernetes/issues/28741
	# 10 ** 0
	mem_multiple("m") = 1 { true }

	# 1000 * 2 ** 10
	mem_multiple("Ki") = 1024000 { true }

	# 1000 * 2 ** 20
	mem_multiple("Mi") = 1048576000 { true }

	# 1000 * 2 ** 30
	mem_multiple("Gi") = 1073741824000 { true }

	# 1000 * 2 ** 40
	mem_multiple("Ti") = 1099511627776000 { true }

	# 1000 * 2 ** 50
	mem_multiple("Pi") = 1125899906842624000 { true }

	# 1000 * 2 ** 60
	mem_multiple("Ei") = 1152921504606846976000 { true }

	get_suffix(mem) = suffix {
	not is_string(mem)
	suffix := ""
	}

	get_suffix(mem) = suffix {
	is_string(mem)
	count(mem) > 0
	suffix := substring(mem, count(mem) - 1, -1)
	mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
	is_string(mem)
	count(mem) > 1
	suffix := substring(mem, count(mem) - 2, -1)
	mem_multiple(suffix)
	}

	get_suffix(mem) = suffix {
	is_string(mem)
	count(mem) > 1
	not mem_multiple(substring(mem, count(mem) - 1, -1))
	not mem_multiple(substring(mem, count(mem) - 2, -1))
	suffix := ""
	}

	get_suffix(mem) = suffix {
	is_string(mem)
	count(mem) == 1
	not mem_multiple(substring(mem, count(mem) - 1, -1))
	suffix := ""
	}

	get_suffix(mem) = suffix {
	is_string(mem)
	count(mem) == 0
	suffix := ""
	}

	canonify_mem(orig) = new {
	is_number(orig)
	new := orig * 1000
	}

	canonify_mem(orig) = new {
	not is_number(orig)
	suffix := get_suffix(orig)
	raw := replace(orig, suffix, "")
	regex.find_n("^[0-9]+(\\.[0-9]+)?$", raw, -1)
	new := to_number(raw) * mem_multiple(suffix)
	}

	deny[msg] {
	general_violation[{"msg": msg, "field": "containers"}]
	}

	deny[msg] {
	general_violation[{"msg": msg, "field": "initContainers"}]
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	cpu_orig := container.resources.requests.cpu
	not canonify_cpu(cpu_orig)
	msg := sprintf("container <%v> cpu request <%v> could not be parsed", [container.name, cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	mem_orig := container.resources.requests.memory
	not canonify_mem(mem_orig)
	msg := sprintf("container <%v> memory request <%v> could not be parsed", [container.name, mem_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	not container.resources
	msg := sprintf("container <%v> has no resource requests", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	not container.resources.requests
	msg := sprintf("container <%v> has no resource requests", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	missing(container.resources.requests, "cpu")
	msg := sprintf("container <%v> has no cpu request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	missing(container.resources.requests, "memory")
	msg := sprintf("container <%v> has no memory request", [container.name])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	cpu_orig := container.resources.requests.cpu
	cpu := canonify_cpu(cpu_orig)
	max_cpu_orig := input.parameters.cpu
	max_cpu := canonify_cpu(max_cpu_orig)
	cpu > max_cpu
	msg := sprintf("container <%v> cpu request <%v> is higher than the maximum allowed of <%v>", [container.name, cpu_orig, max_cpu_orig])
	}

	general_violation[{"msg": msg, "field": field}] {
	container := input.request.object.spec[field][_]
	mem_orig := container.resources.requests.memory
	mem := canonify_mem(mem_orig)
	max_mem_orig := input.parameters.memory
	max_mem := canonify_mem(max_mem_orig)
	mem > max_mem
	msg := sprintf("container <%v> memory request <%v> is higher than the maximum allowed of <%v>", [container.name, mem_orig, max_mem_orig])
	}`,
	232: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	110: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	138: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	225: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	151: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	155: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	185: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	190: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	192: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	19: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	21: `
	package opsmx
	import future.keywords.in
	
	openssf_results_file = concat("_", [input.metadata.owner, input.metadata.repository, input.metadata.build_id])
	openssf_results_file_complete = concat("", [openssf_results_file, "_scorecard.json"])
	
	policy_name = input.conditions[0].condition_name 
	check_orig = replace(replace(policy_name, "Open SSF ", ""), " Policy", "")
	
	check_name = replace(lower(check_orig), " ", "-")
	threshold = to_number(input.conditions[0].condition_value)
	request_url = concat("",[input.metadata.toolchain_addr, "api", "/v1", "/openssfScore?scoreCardName=", openssf_results_file_complete, "&", "checkName=", check_name])
	
	request = {
		"method": "GET",
		"url": request_url,
	}
	
	response = http.send(request)
	
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.body.code == 404
	  msg := ""
	  sugg := sprintf("Results for %v check could not be obtained. Suggests incompatibility between the check and repository. Kindly enable related features and integrations.", [policy_name])
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	  error := sprintf("Error Received: %v.",[response.body.error])
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := ""
	  error := sprintf("Error %v receieved: %v", [response.body.error])
	  sugg := "Kindly check if toolchain service is available in SSD environment and OpenSSF integration Policies are enabled."
	}
	
	default in_range = false
	
	isNumberBetweenTwoNumbers(num, lower, upper) {
		num >= lower
		num <= upper
	}
	
	in_range = isNumberBetweenTwoNumbers(response.body.score, 0, 10)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  in_range == true
	  response.body.score < threshold
	
	  documentation := response.body.documentationUrl 
	  msg := sprintf("%v score for repo %v/%v is %v, which is less than 5 out 10.", [policy_name, input.metadata.owner, input.metadata.repository, response.body.score])
	  sugg := sprintf("%v Check Documentation: %v", [input.metadata.suggestion, documentation])
	  error := ""
	}`,
	111: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	220: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	273: `sample script`,
	99: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	154: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	214: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	282: `
	package opsmx
	default high_severities = []
	
	default multi_alert = false
	default exists_alert = false
	
	exists_alert = check_if_high_alert_exists
	multi_alert = check_if_multi_alert
	
	check_if_high_alert_exists = exists_flag {
	  high_severities_counter = count(input.metadata.results[0].HighSeverity)
	  high_severities_counter > 0
	  exists_flag = true
	}
	
	check_if_multi_alert() = multi_flag {
	  high_severities_counter = count(input.metadata.results[0].HighSeverity)
	  high_severities_counter > 1
	  multi_flag = true
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error }]{
	  check_if_high_alert_exists
	  check_if_multi_alert
	  
	  some i
	  rule = input.metadata.results[0].HighSeverity[i].RuleID
	  title = input.metadata.results[0].HighSeverity[i].Title
	  targets = concat(",\n", input.metadata.results[0].HighSeverity[i].TargetResources)
	  resolution = input.metadata.results[0].HighSeverity[i].Resolution
	  msg := sprintf("Rule ID: %v,\nTitle: %v. \nBelow are the sources of High severity:\n %v", [rule, title, targets])
	  sugg := resolution
	  error := ""
	}`,
	133: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	172: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	271: `
	package opsmx

	import data.strings
	
	body := {
		"image": input.metadata.image,
			"imageTag": input.metadata.image_tag,
			"username": input.metadata.ssd_secret.docker.username,
			"password": input.metadata.ssd_secret.docker.password
	}
	
	request_url = concat("",[input.metadata.toolchain_addr, "/api", "/v1", "/artifactSign"])
	
	request = {
		"method": "POST",
		"url": request_url,
		"body": body
	}
	
	response = http.send(request) 
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
		response.body.code == 500
		msg = sprintf("Artifact %v:%v is not a signed artifact. Kindly verify authenticity of the artifact and its source.",[input.metadata.image, input.metadata.image_tag])
		sugg := ""
		error := ""
	}`,
	250: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
	56: `
	package opsmx

	deny[msg] {
	  # spec.volumes field is immutable.
	  not is_update(input.request)
	
	  volume := input_flexvolumes[_]
	  not input_flexvolumes_allowed(volume)
	  msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.request.object.metadata.name, input.parameters.allowedFlexVolumes])
	}
	
	input_flexvolumes_allowed(volume) {
	  input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
	}
	
	input_flexvolumes[v] {
	  v := input.request.object.spec.volumes[_]
	  has_field(v, "flexVolume")
	}
	
	# has_field returns whether an object has a field
	has_field(object, field) = true {
	  object[field]
	}
	
	is_update(review) {
		review.operation == "UPDATE"
	}`,
	88: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	170: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	219: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	40: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"repos", input.metadata.owner, input.metadata.repository]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	license_url = response.body.license.url
	
	allow {
	  response.status_code = 200
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check repository configuration due to Bad Credentials."
	  error := "401 Unauthorized."
	  sugg := "Kindly check the access token. It must have enough permissions to get repository configurations."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := "Repository not found while trying to fetch Repository Configuration."
	  sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository configuration."
	  error := "Repo name or Organisation is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 301, 302]
	  not response.status_code in codes
	  msg := "Unable to fetch repository configuration."
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch Repository Configuration.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  license_url == null
	  msg := sprintf("GitHub License not found for the %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  sugg := sprintf("Adhere to the company policy by adding a License file for %v/%v repository.", [input.metadata.owner, input.metadata.repository])
	  error := ""
	}`,
	71: `
	package opsmx

	import future.keywords.in
	
	rating_map := {
	  "A": "5.0",
	  "B": "4.0",
	  "C": "3.0",
	  "D": "2.0",
	  "E": "1.0"
	}
	
	required_rating_name := concat("", ["new_", lower(split(input.conditions[0].condition_name, " ")[1]), "_rating"])
	required_rating_score := rating_map[split(input.conditions[0].condition_name, " ")[3]]
	
	request_url = sprintf("%s/api/measures/component?metricKeys=%s&component=%s", [input.metadata.ssd_secret.sonarQube_creds.url, required_rating_name, input.metadata.sonarqube_projectKey])
	
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [input.metadata.ssd_secret.sonarQube_creds.token]),
		},
	}
	default response = ""
	response = http.send(request)
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  input.metadata.sonarqube_projectKey == ""
	  msg := ""
	  error := "Project name not provided."
	  sugg := "Verify the integration of Sonarqube in SSD is configured properly."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response == ""
	  msg := ""
	  error := "Response not received."
	  sugg := "Kindly verify the endpoint provided and the reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := ""
	  error := "Sonarqube host provided is not reponding or is not reachable." 
	  sugg := "Kindly verify the configuration of sonarqube endpoint and reachability of the endpoint."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := ""
	  error := sprintf("Error: 404 Not Found. Project not configured for repository %s.", [input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Please configure project %s in SonarQube.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 403
	  error := sprintf("Error: 403 Forbidden. Provided Token does not have privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	  msg := ""
	  sugg := sprintf("Kindly verify the access token provided is correct and have required privileges to read status of project %s.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  not response.status_code in [500, 404, 403, 200, 302]
	  error := sprintf("Error: %v: %v", [response.status_code])
	  msg := ""
	  sugg := sprintf("Kindly rectify the error while fetching %s project status.", [input.metadata.sonarqube_projectKey])
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code in [200, 302]
	  score = response.body.component.measures[0].period.value
	  score == required_rating_score
	  msg := sprintf("The SonarQube metric %s stands at %s for project %s, falling short of the expected value.", [required_rating_name, score, input.metadata.sonarqube_projectKey])
	  sugg := sprintf("Adhere to code security standards to improve score for project %s.", [input.metadata.sonarqube_projectKey])
	  error := ""
	}`,
	193: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	102: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	238: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	247: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	288: `
	package opsmx
	import future.keywords.in

	default allow = false

	request_url = concat("", [input.metadata.ssd_secret.gitlab.rest_api_url,"api/v4/projects/", input.metadata.gitlab_project_id, "/repository/branches/", input.metadata.branch])

	token = input.metadata.ssd_secret.gitlab.token

	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"PRIVATE-TOKEN": sprintf("%v", [token]),
		},
	}

	response = http.send(request)

	allow {
	response.status_code = 200
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	response.status_code == 401
	msg := ""
	error := "Unauthorized to check repository branch protection policy configuration due to Bad Credentials."
	sugg := "Kindly check the access token. It must have enough permissions to get repository branch protection policy configurations."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 404
	msg := ""
	sugg := "Kindly check if the repository provided is correct and the access token has rights to read repository branch protection policy configuration."
	error := "Mentioned branch for Repository not found while trying to fetch repository branch protection policy configuration."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code == 500
	msg := "Internal Server Error."
	sugg := ""
	error := "Gitlab is not reachable."
	}

	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	codes = [401, 404, 500, 200, 302]
	not response.status_code in codes
	msg := ""
	error := sprintf("Error %v receieved from Gitlab upon trying to fetch Repository Configuration.", [response.body.message])
	sugg := "Kindly check Gitlab API is reachable and the provided access token has required permissions."
	}

	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	response.status_code in [200]
	response.body.protected == false
	msg := sprintf("Branch %v of Gitlab repository %v is not protected by a branch protection policy.", [input.metadata.branch, input.metadata.repository])
	sugg := sprintf("Adhere to the company policy by enforcing Branch Protection Policy for branches of %v Gitlab repository.",[input.metadata.repository])
	error := ""
	}`,
	10: `
	package opsmx
	import future.keywords.in
	
	default allow = false
	
	request_components = [input.metadata.ssd_secret.github.rest_api_url,"orgs", input.metadata.owner, "actions", "permissions", "workflow"]
	request_url = concat("/",request_components)
	
	token = input.metadata.ssd_secret.github.token
	request = {
		"method": "GET",
		"url": request_url,
		"headers": {
			"Authorization": sprintf("Bearer %v", [token]),
		},
	}
	
	response = http.send(request)
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.status_code == 401
	  msg := "Unauthorized to check Organisation Workflow Permissions."
	  error := "401 Unauthorized."
	  sugg := "Kindly check the access token. It must have enough permissions to get organisation workflow permissions."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 404
	  msg := "Mentioned Organisation not found while trying to fetch organisation workflow permissions."
	  sugg := "Kindly check if the organisation provided is correct."
	  error := "Organisation name is incorrect."
	}
	
	deny[{"alertMsg": msg, "suggestion": sugg, "error": error}]{
	  response.status_code == 500
	  msg := "Internal Server Error."
	  sugg := ""
	  error := "GitHub is not reachable."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  codes = [401, 404, 500, 200, 302]
	  not response.status_code in codes
	  msg := "Unable to fetch organisation workflow permissions."
	  error := sprintf("Error %v:%v receieved from Github upon trying to fetch organisation workflow permissions.", [response.status_code, response.body.message])
	  sugg := "Kindly check Github API is reachable and the provided access token has required permissions."
	}
	
	deny[{"alertMsg":msg, "suggestions": sugg, "error": error}]{
	  response.body.default_workflow_permissions != "read"
	  msg := sprintf("Default workflow permissions for Organisation %v is not set to read.", [input.metadata.owner])
	  sugg := sprintf("Adhere to the company policy by enforcing default_workflow_permissions of Organisation %s to read only.", [input.metadata.owner])
	  error := ""
	}`,
	128: `
	package opsmx
import future.keywords.in

deny[{"alertMsg":msg, "suggestion":suggestion, "error":error}] {
  policy = input.conditions[0].condition_name
  
  input.metadata.results[i].control_title == policy
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v on cluster %v due to following resources: %v", [input.metadata.scan_type, policy, input.metadata.account_name, concat(",",failed_resources)])
  error := ""
  suggestion := input.metadata.suggestion
}`,
	245: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]
  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	215: `
	package opsmx
import future.keywords.in

policy = input.conditions[0].condition_name
control_id = split(policy, " -")[0]

  
deny[{"alertMsg":msg, "suggestion":suggestion, "error":""}] {
  input.metadata.results[i].control_id == control_id
  control_struct = input.metadata.results[i]
  failed_resources = control_struct.failed_resources
  counter = count(failed_resources)
  counter > 0
  msg := sprintf("%v scan failed for control %v:%v on cluster %v due to following resources: %v", [input.metadata.scan_type, control_struct.control_id, control_struct.control_title, input.metadata.account_name, concat(",",failed_resources)])
  suggestion := input.metadata.suggestion
}`,
	254: `
	package opsmx

condition_value := input.conditions[0].condition_value
min_threshold_str := split(condition_value, "-")[0]
max_threshold_str := split(condition_value, "-")[1]
min_threshold := to_number(min_threshold_str)
max_threshold := to_number(max_threshold_str)

deny[{"alertMsg":msg, "suggestions": sugg, "error": ""}] {
  score := input.metadata.compliance_score
  score > min_threshold
  score <= max_threshold
  msg := sprintf("%v Scan failed for cluster %v as Compliance Score was found to be %v which is below threshold %v.", [input.metadata.scan_type, input.metadata.account_name, score, max_threshold])
  sugg := input.metadata.suggestion
}`,
}

var policyDefinition = []string{
	`
	{
		 "policyId":"1",
		 "orgId":"1",
		 "policyName":"Repository Access Control Policy",
		 "category":"system",
		 "stage":"source",
		 "description":"Code Repository should not be publicly visible or modifiable.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"1",
		 "variables":"",
		 "conditionName":"Repository Access Control Policy"
	}
	`,
	`
	{
		 "policyId":"2",
		 "orgId":"1",
		 "policyName":"Minimum Reviewers Policy",
		 "category":"system",
		 "stage":"source",
		 "description":"Pushed code should be reviewed by a minimum number of users:2 as defined in the policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"2",
		 "variables":"",
		 "conditionName":"Minimum Reviewers Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"3",
		 "orgId":"1",
		 "policyName":"Branch Protection Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Repositories should have branch protection enabled requiring all code changes to be reviewed. This means disabling Push events and requiring Pull/Merge Requests to have code reviews.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"3",
		 "variables":"",
		 "conditionName":"Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"4",
		 "orgId":"1",
		 "policyName":"Branch Deletion Prevention Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"While the default branch can’t be deleted directly even if the setting is on, in general, it is best practice to prevent branches from being deleted by anyone with write access.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"4",
		 "variables":"",
		 "conditionName":"Branch Deletion Prevention Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"5",
		 "orgId":"1",
		 "policyName":"Commit Signing Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Commit signing should be mandatory. Signing commits is needed because it is pretty easy to add anyone as the author of a commit. Git allows a committer to change the author of a commit easily. In the case of a signed commit, any change to the author will make the commit appear unsigned.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"5",
		 "variables":"",
		 "conditionName":"Commit Signing Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"6",
		 "orgId":"1",
		 "policyName":"Repository 2FA Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Repositories should be protected based on 2FA authentication",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"6",
		 "variables":"",
		 "conditionName":"Repository 2FA Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"7",
		 "orgId":"1",
		 "policyName":"Low Vulnerability Prevention Policy",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Low Severity Vulnerability should not be found in the artifact",
		 "scheduled_policy":true,
		 "datasourceTool":[{"id":"21"}],
		 "scriptId":"7",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"8",
		 "orgId":"1",
		 "policyName":"Critical Vulnerability Prevention Policy",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Critical Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "datasourceTool":[{"id":"21"}],
		 "scriptId":"8",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"9",
		 "orgId":"1",
		 "policyName":"Medium Vulnerability Prevention Policy",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Medium Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "datasourceTool":[{"id":"21"}],
		 "scriptId":"9",
		 "variables":"",
		 "conditionName":"severity",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"10",
		 "orgId":"1",
		 "policyName":"Build Workflow Permissions over Organization Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Build Workflow should have minimum permissions over organization configuration.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"10",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"11",
		 "orgId":"1",
		 "policyName":"Build Workflow Permissions over Repository Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Build Workflow should have minimum permissions over repository configuration",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"11",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"12",
		 "orgId":"1",
		 "policyName":"Identical Build and Cloud Artifact Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Build signature in Build Environment and Cloud Environment during Deployment should be identical to confirm integrity of the artifact.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"4"}],
		 "scriptId":"12",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"13",
		 "orgId":"1",
		 "policyName":"Open SSF Branch Protection Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This evaluates if the project main and release branches are safeguarded with GitHub branch protection settings, enforcing review and status check requirements before merging and preventing history changes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"13",
		 "variables":"",
		 "conditionName":"Open SSF Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"14",
		 "orgId":"1",
		 "policyName":"Open SSF CI Tests Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This assesses if the project enforces running tests before merging pull requests, currently applicable only to GitHub-hosted repositories, excluding other source hosting platforms.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"14",
		 "variables":"",
		 "conditionName":"Open SSF CI Tests Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"15",
		 "orgId":"1",
		 "policyName":"Open SSF CII-Best Practices Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This evaluates if the project has achieved an OpenSSF Best Practices Badge to indicate adherence to security-focused best practices, using the Git repo URL and OpenSSF Badge API",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"15",
		 "variables":"",
		 "conditionName":"Open SSF CII-Best Practices Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"16",
		 "orgId":"1",
		 "policyName":"Open SSF Code Review Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check determines whether the project requires human code review before pull requests are merged.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"16",
		 "variables":"",
		 "conditionName":"Open SSF Code Review Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"17",
		 "orgId":"1",
		 "policyName":"Open SSF Contributors Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check assesses if the project has recent contributors from various organizations, applicable only to GitHub-hosted repositories, without support for other source hosting platforms",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"17",
		 "variables":"",
		 "conditionName":"Open SSF Contributors Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"18",
		 "orgId":"1",
		 "policyName":"Open SSF Dangerous Workflow Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This identifies risky code patterns in the project GitHub Action workflows, such as untrusted code checkouts, logging sensitive information, or using potentially unsafe inputs in scripts",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"18",
		 "variables":"",
		 "conditionName":"Open SSF Dangerous Workflow Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"19",
		 "orgId":"1",
		 "policyName":"Open SSF Dependency Update Tool Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This evaluates if the project utilizes a dependency update tool like Dependabot, Renovate bot, Sonatype Lift, or PyUp to automate updating outdated dependencies and enhance security",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"19",
		 "variables":"",
		 "conditionName":"Open SSF Dependency Update Tool Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"20",
		 "orgId":"1",
		 "policyName":"Open SSF Fuzzing Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This assesses if the project employs fuzzing, considering various criteria including repository inclusion, fuzzing tool presence, language-specific functions, and integration files.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"20",
		 "variables":"",
		 "conditionName":"Open SSF Fuzzing Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"21",
		 "orgId":"1",
		 "policyName":"Open SSF License Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This examines if the project has a published license by using hosting APIs or searching for a license file using standard naming conventions",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"21",
		 "variables":"",
		 "conditionName":"Open SSF License Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"22",
		 "orgId":"1",
		 "policyName":"Open SSF Maintained Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check evaluates project maintenance status based on commit frequency, issue activity, and archival status",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"22",
		 "variables":"",
		 "conditionName":"Open SSF Maintained Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"23",
		 "orgId":"1",
		 "policyName":"Open SSF Pinned Dependencies Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This verifies if a project locks its dependencies to specific versions by their hashes, applicable only to GitHub repositories.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"23",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"24",
		 "orgId":"1",
		 "policyName":"Open SSF Packaging Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This assesses if the project is released as a ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"24",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"25",
		 "orgId":"1",
		 "policyName":"Open SSF SAST Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check assesses if a GitHub-hosted project employs Static Application Security Testing ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"25",
		 "variables":"",
		 "conditionName":"Open SSF SAST Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"26",
		 "orgId":"1",
		 "policyName":"Open SSF Security Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check determines whether the project has generated executable ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"26",
		 "variables":"",
		 "conditionName":"Open SSF Security Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"27",
		 "orgId":"1",
		 "policyName":"Open SSF Signed Releases Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This determines if the project cryptographically signs release artefacts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"27",
		 "variables":"",
		 "conditionName":"Open SSF Signed Releases Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"28",
		 "orgId":"1",
		 "policyName":"Open SSF Token Permissions Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This Determines Whether the project automated workflow tokens follow the principle of least privilege",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"28",
		 "variables":"",
		 "conditionName":"Open SSF Token Permissions Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"29",
		 "orgId":"1",
		 "policyName":"Open SSF Vulnerabilities Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"The Project Has Open, Unfixed Vulnerabilities in its Own codebase.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"29",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"30",
		 "orgId":"1",
		 "policyName":"Open SSF Webhooks Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check determines whether the webhook defined in the repository has a token configured to authenticate the origins of requests.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"30",
		 "variables":"",
		 "conditionName":"Open SSF Webhooks Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"31",
		 "orgId":"1",
		 "policyName":"Open SSF Binary Artifacts Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This check determines whether the project has generated executable ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"31",
		 "variables":"",
		 "conditionName":"Open SSF Binary Artifacts Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"32",
		 "orgId":"1",
		 "policyName":"Restricted Repository Access: Internal Authorization Only",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy limits repository access to internal personnel only, ensuring secure and controlled information management.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"32",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"33",
		 "orgId":"1",
		 "policyName":"Bot User should not be a Repo Admin",
		 "category":"System",
		 "stage":"source",
		 "description":"Bot User should not be a Repo Admin",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"33",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"34",
		 "orgId":"1",
		 "policyName":"Bot User should not be a Org Owner",
		 "category":"System",
		 "stage":"source",
		 "description":"Bot User should not be a Org Owner",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"34",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"35",
		 "orgId":"1",
		 "policyName":"Build Webhook Authenticated Protection Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Webhooks used in workflows should be protected/authenticated.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"35",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"36",
		 "orgId":"1",
		 "policyName":"Build Webhook SSL/TLS Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Webhooks should use SSL/TLS.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"36",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"37",
		 "orgId":"1",
		 "policyName":"Build Server Origin Check",
		 "category":"System",
		 "stage":"build",
		 "description":"Build Server Origin Check is a policy that ensures artifacts originate from approved build servers for secure deployments.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"4"}],
		 "scriptId":"37",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"38",
		 "orgId":"1",
		 "policyName":"Pre-Deployment Checksum Verify",
		 "category":"system",
		 "stage":"artifact",
		 "description":"Pre-Deployment Checksum Verify is a security policy that validates artifact integrity by comparing build-time checksums with Docker checksums, ensuring trusted and unaltered artifacts are used for deployment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"5"},{"id":"6"},{"id":"7"}],
		 "scriptId":"38",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"39",
		 "orgId":"1",
		 "policyName":"Cloud Artifact should match the build artifact by hash",
		 "category":"system",
		 "stage":"deploy",
		 "description":"An image hash not matched to a build artifact may indicate a compromise of the cloud account. An unauthorized application may be running in your organizations cloud.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"39",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"40",
		 "orgId":"1",
		 "policyName":"Repository License Inclusion Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Repositories should contain licence files",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"40",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"41",
		 "orgId":"1",
		 "policyName":"Approved Artifact Repo Origin",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Approved Artifact Repo Origin policy validates artifacts from authorized repositories, ensuring secure deployments.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"5"}],
		 "scriptId":"41",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"42",
		 "orgId":"1",
		 "policyName":"Open SSF Aggregate Score Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"The project might have known security vulnerabilities that have not been adequately  addressed",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"15"}],
		 "scriptId":"42",
		 "variables":"",
		 "conditionName":"Open SSF Aggregate Score Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"43",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating D Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade D rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"43",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"44",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating C Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade C rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"44",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"45",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating B Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade B rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"45",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"46",
		 "orgId":"1",
		 "policyName":"Block Container Without Limits",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Requires containers to have memory and CPU limits set and constrains limits to be within the specified maximum values.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"46",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"47",
		 "orgId":"1",
		 "policyName":"Block Container Without Request Limit",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Requires containers to have memory and CPU requests set and constrains requests to be within the specified maximum values.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"47",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"48",
		 "orgId":"1",
		 "policyName":"SEMGREP High Severity Findings Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of high-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"20"}],
		 "scriptId":"48",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"49",
		 "orgId":"1",
		 "policyName":"SEMGREP Medium Severity Findings Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of medium-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"20"}],
		 "scriptId":"49",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"50",
		 "orgId":"1",
		 "policyName":"Block Undefined Container Ratios",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Sets a maximum ratio for container resource limits to requests.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"50",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"51",
		 "orgId":"1",
		 "policyName":"SAST Integration Validation Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Ensures atleast one SAST tool is configured for Source Repo.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"},{"id":"20"}],
		 "scriptId":"51",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"52",
		 "orgId":"1",
		 "policyName":"SEMGREP Low Severity Findings Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is designed to ensure timely identification, assessment, and resolution of low-severity findings in SEMGREP analysis. It outlines the procedures and responsibilities for addressing issues that could pose significant risks to code quality and security.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"20"}],
		 "scriptId":"52",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"53",
		 "orgId":"1",
		 "policyName":"Pod Security Allow Privilege Escalation",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls restricting escalation to root privileges.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"53",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"54",
		 "orgId":"1",
		 "policyName":"Pod Security App Armor",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Configures an allow-list of AppArmor profiles for use by containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"54",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"55",
		 "orgId":"1",
		 "policyName":"Pod Security Capabilities",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls Linux capabilities on containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"55",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"56",
		 "orgId":"1",
		 "policyName":"Pod Security Flex Volumes",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls the allowlist of FlexVolume drivers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"56",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"57",
		 "orgId":"1",
		 "policyName":"Pod Security Forbidden Sysctl",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls the sysctl profile used by containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"57",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"58",
		 "orgId":"1",
		 "policyName":"Pod Security FS Group",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls allocating an FSGroup that owns the Pods volumes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"58",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"59",
		 "orgId":"1",
		 "policyName":"Pod Security Host Filesystem",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls usage of the host filesystem.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"59",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"60",
		 "orgId":"1",
		 "policyName":"Pod Security Host Namespace",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Disallows sharing of host PID and IPC namespaces by pod containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"60",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"61",
		 "orgId":"1",
		 "policyName":"Pod Security Host Network",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls usage of host network namespace by pod containers. Specific ports must be specified.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"61",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"62",
		 "orgId":"1",
		 "policyName":"Pod Security Privileged Container",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls the ability of any container to enable privileged mode.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"62",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"63",
		 "orgId":"1",
		 "policyName":"Pod Security Proc Mount",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Controls the allowed procMount types for the container.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"63",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"64",
		 "orgId":"1",
		 "policyName":"Pod Security Read Only Root FS",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Requires the use of a read-only root file system by pod containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"64",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"65",
		 "orgId":"1",
		 "policyName":"Pod Security Volume Types",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Restricts mountable volume types to those specified by the user.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"65",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"66",
		 "orgId":"1",
		 "policyName":"SonarQube Quality Gate Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"The purpose of this policy is to comply with SonarQube quality gates, ensuring that code meets predefined quality and performance standards. It emphasizes the importance of continuous code improvement and adherence to best practices.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"66",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"67",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating E Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade E rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"67",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"68",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating D Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade D rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"68",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"69",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating C Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade C rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"69",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"70",
		 "orgId":"1",
		 "policyName":"SonarQube Maintanability Rating B Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy is dedicated to the timely resolution of maintainability issues identified with a Grade B rating in SonarQube. It aims to enhance and sustain code maintainability, streamlining future development efforts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"70",
		 "variables":"",
		 "conditionName":"SonarQube Maintanability Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"71",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating E Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade E rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"71",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"72",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating D Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade D rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"72",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating D Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"73",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating C Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade C rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"73",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating C Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"74",
		 "orgId":"1",
		 "policyName":"SonarQube Security Rating B Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy directs efforts towards improving code security when assigned a Grade B rating in SonarQube. It emphasizes the critical need to fortify the codebase against security threats, protecting sensitive data and preventing potential exploits.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"74",
		 "variables":"",
		 "conditionName":"SonarQube Security Rating B Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"75",
		 "orgId":"1",
		 "policyName":"SonarQube Reliability Rating E Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"This policy aims to promptly resolve reliability issues identified with a Grade E rating in SonarQube. It focuses on enhancing and sustaining code reliability to ensure the codebase operates consistently and reliably.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"19"}],
		 "scriptId":"75",
		 "variables":"",
		 "conditionName":"SonarQube Reliability Rating E Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"76",
		 "orgId":"1",
		 "policyName":"High Vulnerability Prevention Policy",
		 "category":"System",
		 "stage":"artifact",
		 "description":"High Severity Vulnerabilities should not be found in the artifact",
		 "scheduled_policy":true,
		 "datasourceTool":[{"id":"21"}],
		 "scriptId":"76",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"77",
		 "orgId":"1",
		 "policyName":"CIS-1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The API server pod specification file controls various parameters that set the behavior of the API server. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"77",
		 "variables":"",
		 "conditionName":"CIS-1.1.1 Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"78",
		 "orgId":"1",
		 "policyName":"CIS-1.1.2 Ensure that the API server pod specification file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The API server pod specification file controls various parameters that set the behavior of the API server. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"78",
		 "variables":"",
		 "conditionName":"CIS-1.1.2 Ensure that the API server pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"79",
		 "orgId":"1",
		 "policyName":"CIS-1.1.3 Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The controller manager pod specification file controls various parameters that set the behavior of the Controller Manager on the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"79",
		 "variables":"",
		 "conditionName":"CIS-1.1.3 Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"80",
		 "orgId":"1",
		 "policyName":"CIS-1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The controller manager pod specification file controls various parameters that set the behavior of various components of the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"80",
		 "variables":"",
		 "conditionName":"CIS-1.1.4 Ensure that the controller manager pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"81",
		 "orgId":"1",
		 "policyName":"CIS-1.1.5 Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The scheduler pod specification file controls various parameters that set the behavior of the Scheduler service in the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"81",
		 "variables":"",
		 "conditionName":"CIS-1.1.5 Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"82",
		 "orgId":"1",
		 "policyName":"CIS-1.1.6 Ensure that the scheduler pod specification file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The scheduler pod specification file controls various parameters that set the behavior of the kube-scheduler service in the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"82",
		 "variables":"",
		 "conditionName":"CIS-1.1.6 Ensure that the scheduler pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"83",
		 "orgId":"1",
		 "policyName":"CIS-1.1.7 Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the behavior of the etcd service in the master node. etcd is a highly-available key-value store which Kubernetes uses for persistent storage of all of its REST API object. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"83",
		 "variables":"",
		 "conditionName":"CIS-1.1.7 Ensure that the etcd pod specification file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"84",
		 "orgId":"1",
		 "policyName":"CIS-1.1.8 Ensure that the etcd pod specification file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The etcd pod specification file /etc/kubernetes/manifests/etcd.yaml controls various parameters that set the behavior of the etcd service in the master node. etcd is a highly-available key-value store which Kubernetes uses for persistent storage of all of its REST API object. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"84",
		 "variables":"",
		 "conditionName":"CIS-1.1.8 Ensure that the etcd pod specification file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"85",
		 "orgId":"1",
		 "policyName":"CIS-1.1.9 Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Container Network Interface provides various networking options for overlay networking. You should consult their documentation and restrict their respective file permissions to maintain the integrity of those files. Those files should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"85",
		 "variables":"",
		 "conditionName":"CIS-1.1.9 Ensure that the Container Network Interface file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"86",
		 "orgId":"1",
		 "policyName":"CIS-1.1.10 Ensure that the Container Network Interface file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Container Network Interface provides various networking options for overlay networking. You should consult their documentation and restrict their respective file permissions to maintain the integrity of those files. Those files should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"86",
		 "variables":"",
		 "conditionName":"CIS-1.1.10 Ensure that the Container Network Interface file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"87",
		 "orgId":"1",
		 "policyName":"CIS-1.1.11 Ensure that the etcd data directory permissions are set to 700 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should not be readable or writable by any group members or the world.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"87",
		 "variables":"",
		 "conditionName":"CIS-1.1.11 Ensure that the etcd data directory permissions are set to 700 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"88",
		 "orgId":"1",
		 "policyName":"CIS-1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should be owned by etcd:etcd.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"88",
		 "variables":"",
		 "conditionName":"CIS-1.1.12 Ensure that the etcd data directory ownership is set to etcd:etcd",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"89",
		 "orgId":"1",
		 "policyName":"CIS-1.1.13 Ensure that the admin.conf file permissions are set to 600",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The admin.conf is the administrator kubeconfig file defining various settings for the administration of the cluster. This file contains private key and respective certificate allowed to fully manage the cluster. You should restrict its file permissions to maintain the integrity and confidentiality of the file. The file should be readable and writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"89",
		 "variables":"",
		 "conditionName":"CIS-1.1.13 Ensure that the admin.conf file permissions are set to 600",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"90",
		 "orgId":"1",
		 "policyName":"CIS-1.1.14 Ensure that the admin.conf file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The admin.conf file contains the admin credentials for the cluster. You should set its file ownership to maintain the integrity and confidentiality of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"90",
		 "variables":"",
		 "conditionName":"CIS-1.1.14 Ensure that the admin.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"91",
		 "orgId":"1",
		 "policyName":"CIS-1.1.15 Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The scheduler.conf file is the kubeconfig file for the Scheduler. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"91",
		 "variables":"",
		 "conditionName":"CIS-1.1.15 Ensure that the scheduler.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"92",
		 "orgId":"1",
		 "policyName":"CIS-1.1.16 Ensure that the scheduler.conf file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The scheduler.conf file is the kubeconfig file for the Scheduler. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"92",
		 "variables":"",
		 "conditionName":"CIS-1.1.16 Ensure that the scheduler.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"93",
		 "orgId":"1",
		 "policyName":"CIS-1.1.17 Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"93",
		 "variables":"",
		 "conditionName":"CIS-1.1.17 Ensure that the controller-manager.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"94",
		 "orgId":"1",
		 "policyName":"CIS-1.1.18 Ensure that the controller-manager.conf file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The controller-manager.conf file is the kubeconfig file for the Controller Manager. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"94",
		 "variables":"",
		 "conditionName":"CIS-1.1.18 Ensure that the controller-manager.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"95",
		 "orgId":"1",
		 "policyName":"CIS-1.1.19 Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of certificates as part of its operation. You should set the ownership of the directory containing the PKI information and all files in that directory to maintain their integrity. The directory and files should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"95",
		 "variables":"",
		 "conditionName":"CIS-1.1.19 Ensure that the Kubernetes PKI directory and file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"96",
		 "orgId":"1",
		 "policyName":"CIS-1.1.20 Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of certificate files as part of the operation of its components. The permissions on these files should be set to 600 or more restrictive to protect their integrity.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"96",
		 "variables":"",
		 "conditionName":"CIS-1.1.20 Ensure that the Kubernetes PKI certificate file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"97",
		 "orgId":"1",
		 "policyName":"CIS-1.1.21 Ensure that the Kubernetes PKI key file permissions are set to 600",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes makes use of a number of key files as part of the operation of its components. The permissions on these files should be set to 600 to protect their integrity and confidentiality.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"97",
		 "variables":"",
		 "conditionName":"CIS-1.1.21 Ensure that the Kubernetes PKI key file permissions are set to 600",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"98",
		 "orgId":"1",
		 "policyName":"CIS-1.2.1 Ensure that the API Server --anonymous-auth argument is set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the API server. You should rely on authentication to authorize access and disallow anonymous requests. If you are using RBAC authorization, it is generally considered reasonable to allow anonymous access to the API Server for health checks and discovery purposes, and hence this recommendation is not scored. However, you should consider whether anonymous discovery is an acceptable risk for your purposes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"98",
		 "variables":"",
		 "conditionName":"CIS-1.2.1 Ensure that the API Server --anonymous-auth argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"99",
		 "orgId":"1",
		 "policyName":"CIS-1.2.2 Ensure that the API Server --token-auth-file parameter is not set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The token-based authentication utilizes static tokens to authenticate requests to the apiserver. The tokens are stored in clear-text in a file on the apiserver, and cannot be revoked or rotated without restarting the apiserver. Hence, do not use static token-based authentication.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"99",
		 "variables":"",
		 "conditionName":"CIS-1.2.2 Ensure that the API Server --token-auth-file parameter is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"100",
		 "orgId":"1",
		 "policyName":"CIS-1.2.3 Ensure that the API Server --DenyServiceExternalIPs is not set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"This admission controller rejects all net-new usage of the Service field externalIPs. This feature is very powerful ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"100",
		 "variables":"",
		 "conditionName":"CIS-1.2.3 Ensure that the API Server --DenyServiceExternalIPs is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"101",
		 "orgId":"1",
		 "policyName":"CIS-1.2.4 Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The apiserver, by default, does not authenticate itself to the kubelets HTTPS endpoints. The requests from the apiserver are treated anonymously. You should set up certificate-based kubelet authentication to ensure that the apiserver authenticates itself to kubelets when submitting requests.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"101",
		 "variables":"",
		 "conditionName":"CIS-1.2.4 Ensure that the API Server --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"102",
		 "orgId":"1",
		 "policyName":"CIS-1.2.5 Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"102",
		 "variables":"",
		 "conditionName":"CIS-1.2.5 Ensure that the API Server --kubelet-certificate-authority argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"103",
		 "orgId":"1",
		 "policyName":"CIS-1.2.6 Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The API Server, can be configured to allow all requests. This mode should not be used on any production cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"103",
		 "variables":"",
		 "conditionName":"CIS-1.2.6 Ensure that the API Server --authorization-mode argument is not set to AlwaysAllow",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"104",
		 "orgId":"1",
		 "policyName":"CIS-1.2.7 Ensure that the API Server --authorization-mode argument includes Node",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The Node authorization mode only allows kubelets to read Secret, ConfigMap, PersistentVolume, and PersistentVolumeClaim objects associated with their nodes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"104",
		 "variables":"",
		 "conditionName":"CIS-1.2.7 Ensure that the API Server --authorization-mode argument includes Node",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"105",
		 "orgId":"1",
		 "policyName":"CIS-1.2.8 Ensure that the API Server --authorization-mode argument includes RBAC",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Role Based Access Control ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"105",
		 "variables":"",
		 "conditionName":"CIS-1.2.8 Ensure that the API Server --authorization-mode argument includes RBAC",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"106",
		 "orgId":"1",
		 "policyName":"CIS-1.2.9 Ensure that the admission control plugin EventRateLimit is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Using EventRateLimit admission control enforces a limit on the number of events that the API Server will accept in a given time slice. A misbehaving workload could overwhelm and DoS the API Server, making it unavailable. This particularly applies to a multi-tenant cluster, where there might be a small percentage of misbehaving tenants which could have a significant impact on the performance of the cluster overall. Hence, it is recommended to limit the rate of events that the API server will accept. Note: This is an Alpha feature in the Kubernetes 1.15 release.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"106",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"107",
		 "orgId":"1",
		 "policyName":"CIS-1.2.10 Ensure that the admission control plugin AlwaysAdmit is not set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Setting admission control plugin AlwaysAdmit allows all requests and do not filter any requests. The AlwaysAdmit admission controller was deprecated in Kubernetes v1.13. Its behavior was equivalent to turning off all admission controllers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"107",
		 "variables":"",
		 "conditionName":"CIS-1.2.10 Ensure that the admission control plugin AlwaysAdmit is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"108",
		 "orgId":"1",
		 "policyName":"CIS-1.2.11 Ensure that the admission control plugin AlwaysPullImages is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Setting admission control policy to AlwaysPullImages forces every new pod to pull the required images every time. In a multi-tenant cluster users can be assured that their private images can only be used by those who have the credentials to pull them. Without this admission control policy, once an image has been pulled to a node, any pod from any user can use it simply by knowing the images name, without any authorization check against the image ownership. When this plug-in is enabled, images are always pulled prior to starting containers, which means valid credentials are required.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"108",
		 "variables":"",
		 "conditionName":"CIS-1.2.11 Ensure that the admission control plugin AlwaysPullImages is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"109",
		 "orgId":"1",
		 "policyName":"CIS-1.2.12 Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
		 "category":"System",
		 "stage":"deploy",
		 "description":"SecurityContextDeny can be used to provide a layer of security for clusters which do not have PodSecurityPolicies enabled.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"109",
		 "variables":"",
		 "conditionName":"CIS-1.2.12 Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"110",
		 "orgId":"1",
		 "policyName":"CIS-1.2.13 Ensure that the admission control plugin ServiceAccount is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"When you create a pod, if you do not specify a service account, it is automatically assigned the default service account in the same namespace. You should create your own service account and let the API server manage its security tokens.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"110",
		 "variables":"",
		 "conditionName":"CIS-1.2.13 Ensure that the admission control plugin ServiceAccount is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"111",
		 "orgId":"1",
		 "policyName":"CIS-1.2.14 Ensure that the admission control plugin NamespaceLifecycle is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Setting admission control policy to NamespaceLifecycle ensures that objects cannot be created in non-existent namespaces, and that namespaces undergoing termination are not used for creating the new objects. This is recommended to enforce the integrity of the namespace termination process and also for the availability of the newer objects.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"111",
		 "variables":"",
		 "conditionName":"CIS-1.2.14 Ensure that the admission control plugin NamespaceLifecycle is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"112",
		 "orgId":"1",
		 "policyName":"CIS-1.2.15 Ensure that the admission control plugin NodeRestriction is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Using the NodeRestriction plug-in ensures that the kubelet is restricted to the Node and Pod objects that it could modify as defined. Such kubelets will only be allowed to modify their own Node API object, and only modify Pod API objects that are bound to their node.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"112",
		 "variables":"",
		 "conditionName":"CIS-1.2.15 Ensure that the admission control plugin NodeRestriction is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"113",
		 "orgId":"1",
		 "policyName":"CIS-1.2.16 Ensure that the API Server --secure-port argument is not set to 0",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The secure port is used to serve https with authentication and authorization. If you disable it, no https traffic is served and all traffic is served unencrypted.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"113",
		 "variables":"",
		 "conditionName":"CIS-1.2.16 Ensure that the API Server --secure-port argument is not set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"114",
		 "orgId":"1",
		 "policyName":"CIS-1.2.17 Ensure that the API Server --profiling argument is set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"114",
		 "variables":"",
		 "conditionName":"CIS-1.2.17 Ensure that the API Server --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"115",
		 "orgId":"1",
		 "policyName":"CIS-1.2.18 Ensure that the API Server --audit-log-path argument is set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Auditing the Kubernetes API Server provides a security-relevant chronological set of records documenting the sequence of activities that have affected system by individual users, administrators or other components of the system. Even though currently, Kubernetes provides only basic audit capabilities, it should be enabled. You can enable it by setting an appropriate audit log path.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"115",
		 "variables":"",
		 "conditionName":"CIS-1.2.18 Ensure that the API Server --audit-log-path argument is set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"116",
		 "orgId":"1",
		 "policyName":"CIS-1.2.19 Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Retaining logs for at least 30 days ensures that you can go back in time and investigate or correlate any events. Set your audit log retention period to 30 days or as per your business requirements.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"116",
		 "variables":"",
		 "conditionName":"CIS-1.2.19 Ensure that the API Server --audit-log-maxage argument is set to 30 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"117",
		 "orgId":"1",
		 "policyName":"CIS-1.2.20 Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for carrying out any investigation or correlation. For example, if you have set file size of 100 MB and the number of old log files to keep as 10, you would approximate have 1 GB of log data that you could potentially use for your analysis.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"117",
		 "variables":"",
		 "conditionName":"CIS-1.2.20 Ensure that the API Server --audit-log-maxbackup argument is set to 10 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"118",
		 "orgId":"1",
		 "policyName":"CIS-1.2.21 Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes automatically rotates the log files. Retaining old log files ensures that you would have sufficient log data available for carrying out any investigation or correlation. If you have set file size of 100 MB and the number of old log files to keep as 10, you would approximate have 1 GB of log data that you could potentially use for your analysis.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"118",
		 "variables":"",
		 "conditionName":"CIS-1.2.21 Ensure that the API Server --audit-log-maxsize argument is set to 100 or as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"119",
		 "orgId":"1",
		 "policyName":"CIS-1.2.22 Ensure that the API Server --request-timeout argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Setting global request timeout allows extending the API server request timeout limit to a duration appropriate to the users connection speed. By default, it is set to 60 seconds which might be problematic on slower connections making cluster resources inaccessible once the data volume for requests exceeds what can be transmitted in 60 seconds. But, setting this timeout limit to be too large can exhaust the API server resources making it prone to Denial-of-Service attack. Hence, it is recommended to set this limit as appropriate and change the default limit of 60 seconds only if needed.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"119",
		 "variables":"",
		 "conditionName":"CIS-1.2.22 Ensure that the API Server --request-timeout argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"120",
		 "orgId":"1",
		 "policyName":"CIS-1.2.23 Ensure that the API Server --service-account-lookup argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"If --service-account-lookup is not enabled, the apiserver only verifies that the authentication token is valid, and does not validate that the service account token mentioned in the request is actually present in etcd. This allows using a service account token even after the corresponding service account is deleted. This is an example of time of check to time of use security issue.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"120",
		 "variables":"",
		 "conditionName":"CIS-1.2.23 Ensure that the API Server --service-account-lookup argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"121",
		 "orgId":"1",
		 "policyName":"CIS-1.2.24 Ensure that the API Server --service-account-key-file argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"By default, if no --service-account-key-file is specified to the apiserver, it uses the private key from the TLS serving certificate to verify service account tokens. To ensure that the keys for service account tokens could be rotated as needed, a separate public/private key pair should be used for signing service account tokens. Hence, the public key should be specified to the apiserver with --service-account-key-file.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"121",
		 "variables":"",
		 "conditionName":"CIS-1.2.24 Ensure that the API Server --service-account-key-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"122",
		 "orgId":"1",
		 "policyName":"CIS-1.2.25 Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be protected by client authentication. This requires the API server to identify itself to the etcd server using a client certificate and key.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"122",
		 "variables":"",
		 "conditionName":"CIS-1.2.25 Ensure that the API Server --etcd-certfile and --etcd-keyfile arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"123",
		 "orgId":"1",
		 "policyName":"CIS-1.2.26 Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"API server communication contains sensitive parameters that should remain encrypted in transit. Configure the API server to serve only HTTPS traffic.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"123",
		 "variables":"",
		 "conditionName":"CIS-1.2.26 Ensure that the API Server --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"124",
		 "orgId":"1",
		 "policyName":"CIS-1.2.27 Ensure that the API Server --client-ca-file argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"API server communication contains sensitive parameters that should remain encrypted in transit. Configure the API server to serve only HTTPS traffic. If --client-ca-file argument is set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"124",
		 "variables":"",
		 "conditionName":"CIS-1.2.27 Ensure that the API Server --client-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"125",
		 "orgId":"1",
		 "policyName":"CIS-1.2.28 Ensure that the API Server --etcd-cafile argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be protected by client authentication. This requires the API server to identify itself to the etcd server using a SSL Certificate Authority file.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"125",
		 "variables":"",
		 "conditionName":"CIS-1.2.28 Ensure that the API Server --etcd-cafile argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"126",
		 "orgId":"1",
		 "policyName":"CIS-1.2.29 Ensure that the API Server --encryption-provider-config argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted at rest to avoid any disclosures.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"126",
		 "variables":"",
		 "conditionName":"CIS-1.2.29 Ensure that the API Server --encryption-provider-config argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"127",
		 "orgId":"1",
		 "policyName":"CIS-1.2.30 Ensure that encryption providers are appropriately configured",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Where etcd encryption is used, it is important to ensure that the appropriate set of encryption providers is used. Currently, the aescbc, kms and secretbox are likely to be appropriate options.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"127",
		 "variables":"",
		 "conditionName":"CIS-1.2.30 Ensure that encryption providers are appropriately configured",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"128",
		 "orgId":"1",
		 "policyName":"CIS-1.2.31 Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"128",
		 "variables":"",
		 "conditionName":"CIS-1.2.31 Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"129",
		 "orgId":"1",
		 "policyName":"CIS-1.3.1 Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Garbage collection is important to ensure sufficient resource availability and avoiding degraded performance and availability. In the worst case, the system might crash or just be unusable for a long period of time. The current setting for garbage collection is 12,500 terminated pods which might be too high for your system to sustain. Based on your system resources and tests, choose an appropriate threshold value to activate garbage collection.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"129",
		 "variables":"",
		 "conditionName":"CIS-1.3.1 Ensure that the Controller Manager --terminated-pod-gc-threshold argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"130",
		 "orgId":"1",
		 "policyName":"CIS-1.3.2 Ensure that the Controller Manager --profiling argument is set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"130",
		 "variables":"",
		 "conditionName":"CIS-1.3.2 Ensure that the Controller Manager --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"131",
		 "orgId":"1",
		 "policyName":"CIS-1.3.3 Ensure that the Controller Manager --use-service-account-credentials argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The controller manager creates a service account per controller in the kube-system namespace, generates a credential for it, and builds a dedicated API client with that service account credential for each controller loop to use. Setting the --use-service-account-credentials to true runs each control loop within the controller manager using a separate service account credential. When used in combination with RBAC, this ensures that the control loops run with the minimum permissions required to perform their intended tasks.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"131",
		 "variables":"",
		 "conditionName":"CIS-1.3.3 Ensure that the Controller Manager --use-service-account-credentials argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"132",
		 "orgId":"1",
		 "policyName":"CIS-1.3.4 Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"To ensure that keys for service account tokens can be rotated as needed, a separate public/private key pair should be used for signing service account tokens. The private key should be specified to the controller manager with --service-account-private-key-file as appropriate.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"132",
		 "variables":"",
		 "conditionName":"CIS-1.3.4 Ensure that the Controller Manager --service-account-private-key-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"133",
		 "orgId":"1",
		 "policyName":"CIS-1.3.5 Ensure that the Controller Manager --root-ca-file argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Processes running within pods that need to contact the API server must verify the API servers serving certificate. Failing to do so could be a subject to man-in-the-middle attacks. Providing the root certificate for the API servers serving certificate to the controller manager with the --root-ca-file argument allows the controller manager to inject the trusted bundle into pods so that they can verify TLS connections to the API server.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"133",
		 "variables":"",
		 "conditionName":"CIS-1.3.5 Ensure that the Controller Manager --root-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"134",
		 "orgId":"1",
		 "policyName":"CIS-1.3.6 Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"134",
		 "variables":"",
		 "conditionName":"CIS-1.3.6 Ensure that the Controller Manager RotateKubeletServerCertificate argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"135",
		 "orgId":"1",
		 "policyName":"CIS-1.3.7 Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The Controller Manager API service which runs on port 10252/TCP by default is used for health and metrics information and is available without authentication or encryption. As such it should only be bound to a localhost interface, to minimize the clusters attack surface.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"135",
		 "variables":"",
		 "conditionName":"CIS-1.3.7 Ensure that the Controller Manager --bind-address argument is set to 127.0.0.1",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"136",
		 "orgId":"1",
		 "policyName":"CIS-1.4.1 Ensure that the Scheduler --profiling argument is set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"136",
		 "variables":"",
		 "conditionName":"CIS-1.4.1 Ensure that the Scheduler --profiling argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"137",
		 "orgId":"1",
		 "policyName":"CIS-1.4.2 Ensure that the Scheduler --bind-address argument is set to 127.0.0.1",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The Scheduler API service which runs on port 10251/TCP by default is used for health and metrics information and is available without authentication or encryption. As such it should only be bound to a localhost interface, to minimize the clusters attack surface.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"137",
		 "variables":"",
		 "conditionName":"CIS-1.4.2 Ensure that the Scheduler --bind-address argument is set to 127.0.0.1",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"138",
		 "orgId":"1",
		 "policyName":"CIS-2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"138",
		 "variables":"",
		 "conditionName":"CIS-2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"139",
		 "orgId":"1",
		 "policyName":"CIS-2.2 Ensure that the --client-cert-auth argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"139",
		 "variables":"",
		 "conditionName":"CIS-2.2 Ensure that the --client-cert-auth argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"140",
		 "orgId":"1",
		 "policyName":"CIS-2.3 Ensure that the --auto-tls argument is not set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"140",
		 "variables":"",
		 "conditionName":"CIS-2.3 Ensure that the --auto-tls argument is not set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"141",
		 "orgId":"1",
		 "policyName":"CIS-2.4 Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit and also amongst peers in the etcd clusters.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"141",
		 "variables":"",
		 "conditionName":"CIS-2.4 Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"142",
		 "orgId":"1",
		 "policyName":"CIS-2.5 Ensure that the --peer-client-cert-auth argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"142",
		 "variables":"",
		 "conditionName":"CIS-2.5 Ensure that the --peer-client-cert-auth argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"143",
		 "orgId":"1",
		 "policyName":"CIS-2.6 Ensure that the --peer-auto-tls argument is not set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. Hence, do not use self-signed certificates for authentication.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"143",
		 "variables":"",
		 "conditionName":"CIS-2.6 Ensure that the --peer-auto-tls argument is not set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"144",
		 "orgId":"1",
		 "policyName":"CIS-2.7 Ensure that a unique Certificate Authority is used for etcd",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. Its access should be restricted to specifically designated clients and peers only. Authentication to etcd is based on whether the certificate presented was issued by a trusted certificate authority. There is no checking of certificate attributes such as common name or subject alternative name. As such, if any attackers were able to gain access to any certificate issued by the trusted certificate authority, they would be able to gain full access to the etcd database.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"144",
		 "variables":"",
		 "conditionName":"CIS-2.7 Ensure that a unique Certificate Authority is used for etcd",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"145",
		 "orgId":"1",
		 "policyName":"CIS-3.2.1 Ensure that a minimal audit policy is created",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes can audit the details of requests made to the API server. The --audit-policy-file flag must be set for this logging to be enabled.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"145",
		 "variables":"",
		 "conditionName":"CIS-3.2.1 Ensure that a minimal audit policy is created",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"146",
		 "orgId":"1",
		 "policyName":"CIS-3.2.2 Ensure that the audit policy covers key security concerns",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Security audit logs should cover access and modification of key resources in the cluster, to enable them to form an effective part of a security environment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"146",
		 "variables":"",
		 "conditionName":"CIS-3.2.2 Ensure that the audit policy covers key security concerns",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"147",
		 "orgId":"1",
		 "policyName":"CIS-4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"147",
		 "variables":"",
		 "conditionName":"CIS-4.1.1 Ensure that the kubelet service file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"148",
		 "orgId":"1",
		 "policyName":"CIS-4.1.2 Ensure that the kubelet service file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet service file controls various parameters that set the behavior of the kubelet service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"148",
		 "variables":"",
		 "conditionName":"CIS-4.1.2 Ensure that the kubelet service file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"149",
		 "orgId":"1",
		 "policyName":"CIS-4.1.3 If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kube-proxy kubeconfig file controls various parameters of the kube-proxy service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system. It is possible to run kube-proxy with the kubeconfig parameters configured as a Kubernetes ConfigMap instead of a file. In this case, there is no proxy kubeconfig file.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"149",
		 "variables":"",
		 "conditionName":"CIS-4.1.3 If proxy kubeconfig file exists ensure permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"150",
		 "orgId":"1",
		 "policyName":"CIS-4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubeconfig file for kube-proxy controls various parameters for the kube-proxy service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"150",
		 "variables":"",
		 "conditionName":"CIS-4.1.4 If proxy kubeconfig file exists ensure ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"151",
		 "orgId":"1",
		 "policyName":"CIS-4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"151",
		 "variables":"",
		 "conditionName":"CIS-4.1.5 Ensure that the --kubeconfig kubelet.conf file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"152",
		 "orgId":"1",
		 "policyName":"CIS-4.1.6 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet.conf file is the kubeconfig file for the node, and controls various parameters that set the behavior and identity of the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"152",
		 "variables":"",
		 "conditionName":"CIS-4.1.6 Ensure that the --kubeconfig kubelet.conf file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"153",
		 "orgId":"1",
		 "policyName":"CIS-4.1.7 Ensure that the certificate authorities file permissions are set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The certificate authorities file controls the authorities used to validate API requests. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"153",
		 "variables":"",
		 "conditionName":"CIS-4.1.7 Ensure that the certificate authorities file permissions are set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"154",
		 "orgId":"1",
		 "policyName":"CIS-4.1.8 Ensure that the client certificate authorities file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The certificate authorities file controls the authorities used to validate API requests. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"154",
		 "variables":"",
		 "conditionName":"CIS-4.1.8 Ensure that the client certificate authorities file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"155",
		 "orgId":"1",
		 "policyName":"CIS-4.1.9 If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file is specified you should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"155",
		 "variables":"",
		 "conditionName":"CIS-4.1.9 If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"156",
		 "orgId":"1",
		 "policyName":"CIS-4.1.10 If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The kubelet reads various parameters, including security settings, from a config file specified by the --config argument. If this file is specified you should restrict its file permissions to maintain the integrity of the file. The file should be owned by root:root.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"156",
		 "variables":"",
		 "conditionName":"CIS-4.1.10 If the kubelet config.yaml configuration file is being used validate file ownership is set to root:root",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"157",
		 "orgId":"1",
		 "policyName":"CIS-4.2.1 Ensure that the --anonymous-auth argument is set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the Kubelet server. You should rely on authentication to authorize access and disallow anonymous requests.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"157",
		 "variables":"",
		 "conditionName":"CIS-4.2.1 Ensure that the --anonymous-auth argument is set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"158",
		 "orgId":"1",
		 "policyName":"CIS-4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubelets, by default, allow all authenticated requests ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"158",
		 "variables":"",
		 "conditionName":"CIS-4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"159",
		 "orgId":"1",
		 "policyName":"CIS-4.2.3 Ensure that the --client-ca-file argument is set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"159",
		 "variables":"",
		 "conditionName":"CIS-4.2.3 Ensure that the --client-ca-file argument is set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"160",
		 "orgId":"1",
		 "policyName":"CIS-4.2.4 Verify that the --read-only-port argument is set to 0",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The Kubelet process provides a read-only API in addition to the main Kubelet API. Unauthenticated access is provided to this read-only API which could possibly retrieve potentially sensitive information about the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"160",
		 "variables":"",
		 "conditionName":"CIS-4.2.4 Verify that the --read-only-port argument is set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"161",
		 "orgId":"1",
		 "policyName":"CIS-4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Setting idle timeouts ensures that you are protected against Denial-of-Service attacks, inactive connections and running out of ephemeral ports. Note: By default, --streaming-connection-idle-timeout is set to 4 hours which might be too high for your environment. Setting this as appropriate would additionally ensure that such streaming connections are timed out after serving legitimate use cases.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"161",
		 "variables":"",
		 "conditionName":"CIS-4.2.5 Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"162",
		 "orgId":"1",
		 "policyName":"CIS-4.2.6 Ensure that the --protect-kernel-defaults argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kernel parameters are usually tuned and hardened by the system administrators before putting the systems into production. These parameters protect the kernel and the system. Your kubelet kernel defaults that rely on such parameters should be appropriately set to match the desired secured system state. Ignoring this could potentially lead to running pods with undesired kernel behavior.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"162",
		 "variables":"",
		 "conditionName":"CIS-4.2.6 Ensure that the --protect-kernel-defaults argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"163",
		 "orgId":"1",
		 "policyName":"CIS-4.2.7 Ensure that the --make-iptables-util-chains argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubelets can automatically manage the required changes to iptables based on how you choose your networking options for the pods. It is recommended to let kubelets manage the changes to iptables. This ensures that the iptables configuration remains in sync with pods networking configuration. Manually configuring iptables with dynamic pod network configuration changes might hamper the communication between pods/containers and to the outside world. You might have iptables rules too restrictive or too open.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"163",
		 "variables":"",
		 "conditionName":"CIS-4.2.7 Ensure that the --make-iptables-util-chains argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"164",
		 "orgId":"1",
		 "policyName":"CIS-4.2.8 Ensure that the --hostname-override argument is not set",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overriding hostnames could potentially break TLS setup between the kubelet and the apiserver. Additionally, with overridden hostnames, it becomes increasingly difficult to associate logs with a particular node and process them for security analytics. Hence, you should setup your kubelet nodes with resolvable FQDNs and avoid overriding the hostnames with IPs.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"164",
		 "variables":"",
		 "conditionName":"CIS-4.2.8 Ensure that the --hostname-override argument is not set",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"165",
		 "orgId":"1",
		 "policyName":"CIS-4.2.9 Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
		 "category":"System",
		 "stage":"deploy",
		 "description":"It is important to capture all events and not restrict event creation. Events are an important source of security information and analytics that ensure that your environment is consistently monitored using the event data.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"165",
		 "variables":"",
		 "conditionName":"CIS-4.2.9 Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"166",
		 "orgId":"1",
		 "policyName":"CIS-4.2.10 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"166",
		 "variables":"",
		 "conditionName":"CIS-4.2.10 Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"167",
		 "orgId":"1",
		 "policyName":"CIS-4.2.11 Ensure that the --rotate-certificates argument is not set to false",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The --rotate-certificates setting causes the kubelet to rotate its client certificates by creating new CSRs as its existing credentials expire. This automated periodic rotation ensures that the there is no downtime due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"167",
		 "variables":"",
		 "conditionName":"CIS-4.2.11 Ensure that the --rotate-certificates argument is not set to false",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"168",
		 "orgId":"1",
		 "policyName":"CIS-4.2.12 Verify that the RotateKubeletServerCertificate argument is set to true",
		 "category":"System",
		 "stage":"deploy",
		 "description":"RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"168",
		 "variables":"",
		 "conditionName":"CIS-4.2.12 Verify that the RotateKubeletServerCertificate argument is set to true",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"169",
		 "orgId":"1",
		 "policyName":"CIS-4.2.13 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"TLS ciphers have had a number of known vulnerabilities and weaknesses, which can reduce the protection provided by them. By default Kubernetes supports a number of TLS ciphersuites including some that have security concerns, weakening the protection provided.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"169",
		 "variables":"",
		 "conditionName":"CIS-4.2.13 Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"170",
		 "orgId":"1",
		 "policyName":"CIS-5.1.1 Ensure that the cluster-admin role is only used where required",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes provides a set of default roles where RBAC is used. Some of these roles such as cluster-admin provide wide-ranging privileges which should only be applied where absolutely necessary. Roles such as cluster-admin allow super-user access to perform any action on any resource. When used in a ClusterRoleBinding, it gives full control over every resource in the cluster and in all namespaces. When used in a RoleBinding, it gives full control over every resource in the rolebindings namespace, including the namespace itself.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"170",
		 "variables":"",
		 "conditionName":"CIS-5.1.1 Ensure that the cluster-admin role is only used where required",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"171",
		 "orgId":"1",
		 "policyName":"CIS-5.1.2 Minimize access to secrets",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Inappropriate access to secrets stored within the Kubernetes cluster can allow for an attacker to gain additional access to the Kubernetes cluster or external resources whose credentials are stored as secrets.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"171",
		 "variables":"",
		 "conditionName":"CIS-5.1.2 Minimize access to secrets",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"172",
		 "orgId":"1",
		 "policyName":"CIS-5.1.3 Minimize wildcard use in Roles and ClusterRoles",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The principle of least privilege recommends that users are provided only the access required for their role and nothing more. The use of wildcard rights grants is likely to provide excessive rights to the Kubernetes API.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"172",
		 "variables":"",
		 "conditionName":"CIS-5.1.3 Minimize wildcard use in Roles and ClusterRoles",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"173",
		 "orgId":"1",
		 "policyName":"CIS-5.1.4 Minimize access to create pods",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The ability to create pods in a cluster opens up possibilities for privilege escalation and should be restricted, where possible.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"173",
		 "variables":"",
		 "conditionName":"CIS-5.1.4 Minimize access to create pods",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"174",
		 "orgId":"1",
		 "policyName":"CIS-5.1.5 Ensure that default service accounts are not actively used",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes provides a default service account which is used by cluster workloads where no specific service account is assigned to the pod. Where access to the Kubernetes API from a pod is required, a specific service account should be created for that pod, and rights granted to that service account. The default service account should be configured such that it does not provide a service account token and does not have any explicit rights assignments.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"174",
		 "variables":"",
		 "conditionName":"CIS-5.1.5 Ensure that default service accounts are not actively used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"175",
		 "orgId":"1",
		 "policyName":"CIS-5.1.6 Ensure that Service Account Tokens are only mounted where necessary",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Mounting service account tokens inside pods can provide an avenue for privilege escalation attacks where an attacker is able to compromise a single pod in the cluster. Avoiding mounting these tokens removes this attack avenue.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"175",
		 "variables":"",
		 "conditionName":"CIS-5.1.6 Ensure that Service Account Tokens are only mounted where necessary",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"176",
		 "orgId":"1",
		 "policyName":"CIS-5.1.8 Limit use of the Bind",
		 "category":" Impersonate and Escalate permissions in the Kubernetes cluster",
		 "stage":"System",
		 "description":"The impersonate privilege allows a subject to impersonate other users gaining their rights to the cluster. The bind privilege allows the subject to add a binding to a cluster role or role which escalates their effective permissions in the cluster. The escalate privilege allows a subject to modify cluster roles to which they are bound, increasing their rights to that level. Each of these permissions has the potential to allow for privilege escalation to cluster-admin level.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"176",
		 "variables":"",
		 "conditionName":"CIS-5.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"177",
		 "orgId":"1",
		 "policyName":"CIS-5.2.1 Ensure that the cluster has at least one active policy control mechanism in place",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Without an active policy control mechanism, it is not possible to limit the use of containers with access to underlying cluster nodes, via mechanisms like privileged containers, or the use of hostPath volume mounts.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"177",
		 "variables":"",
		 "conditionName":"CIS-5.2.1 Ensure that the cluster has at least one active policy control mechanism in place",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"178",
		 "orgId":"1",
		 "policyName":"CIS-5.2.2 Minimize the admission of privileged containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Privileged containers have access to all Linux Kernel capabilities and devices. A container running with full privileges can do almost everything that the host can do. This flag exists to allow special use-cases, like manipulating the network stack and accessing devices. There should be at least one admission control policy defined which does not permit privileged containers. If you need to run privileged containers, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"178",
		 "variables":"",
		 "conditionName":"CIS-5.2.2 Minimize the admission of privileged containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"179",
		 "orgId":"1",
		 "policyName":"CIS-5.2.3 Minimize the admission of containers wishing to share the host process ID namespace",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A container running in the hosts PID namespace can inspect processes running outside the container. If the container also has access to ptrace capabilities this can be used to escalate privileges outside of the container. There should be at least one admission control policy defined which does not permit containers to share the host PID namespace. If you need to run containers which require hostPID, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"179",
		 "variables":"",
		 "conditionName":"CIS-5.2.3 Minimize the admission of containers wishing to share the host process ID namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"180",
		 "orgId":"1",
		 "policyName":"CIS-5.2.4 Minimize the admission of containers wishing to share the host IPC namespace",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A container running in the hosts IPC namespace can use IPC to interact with processes outside the container. There should be at least one admission control policy defined which does not permit containers to share the host IPC namespace. If you need to run containers which require hostIPC, this should be definited in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"180",
		 "variables":"",
		 "conditionName":"CIS-5.2.4 Minimize the admission of containers wishing to share the host IPC namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"181",
		 "orgId":"1",
		 "policyName":"CIS-5.2.5 Minimize the admission of containers wishing to share the host network namespace",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A container running in the hosts network namespace could access the local loopback device, and could access network traffic to and from other pods. There should be at least one admission control policy defined which does not permit containers to share the host network namespace. If you need to run containers which require access to the hosts network namesapces, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"181",
		 "variables":"",
		 "conditionName":"CIS-5.2.5 Minimize the admission of containers wishing to share the host network namespace",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"182",
		 "orgId":"1",
		 "policyName":"CIS-5.2.6 Minimize the admission of containers with allowPrivilegeEscalation",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A container running with the allowPrivilegeEscalation flag set to true may have processes that can gain more privileges than their parent. There should be at least one admission control policy defined which does not permit containers to allow privilege escalation. The option exists ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"182",
		 "variables":"",
		 "conditionName":"CIS-5.2.6 Minimize the admission of containers with allowPrivilegeEscalation",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"183",
		 "orgId":"1",
		 "policyName":"CIS-5.2.7 Minimize the admission of root containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Containers may run as any Linux user. Containers which run as the root user, whilst constrained by Container Runtime security features still have a escalated likelihood of container breakout. Ideally, all containers should run as a defined non-UID 0 user. There should be at least one admission control policy defined which does not permit root containers. If you need to run root containers, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"183",
		 "variables":"",
		 "conditionName":"CIS-5.2.7 Minimize the admission of root containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"184",
		 "orgId":"1",
		 "policyName":"CIS-5.2.8 Minimize the admission of containers with the NET_RAW capability",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. By default this can include potentially dangerous capabilities. With Docker as the container runtime the NET_RAW capability is enabled which may be misused by malicious containers. Ideally, all containers should drop this capability. There should be at least one admission control policy defined which does not permit containers with the NET_RAW capability. If you need to run containers with this capability, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"184",
		 "variables":"",
		 "conditionName":"CIS-5.2.8 Minimize the admission of containers with the NET_RAW capability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"185",
		 "orgId":"1",
		 "policyName":"CIS-5.2.9 Minimize the admission of containers with added capabilities",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities outside this set can be added to containers which could expose them to risks of container breakout attacks. There should be at least one policy defined which prevents containers with capabilities beyond the default set from launching. If you need to run containers with additional capabilities, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"185",
		 "variables":"",
		 "conditionName":"CIS-5.2.9 Minimize the admission of containers with added capabilities",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"186",
		 "orgId":"1",
		 "policyName":"CIS-5.2.10 Minimize the admission of containers with capabilities assigned",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities are parts of the rights generally granted on a Linux system to the root user. In many cases applications running in containers do not require any capabilities to operate, so from the perspective of the principal of least privilege use of capabilities should be minimized.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"186",
		 "variables":"",
		 "conditionName":"CIS-5.2.10 Minimize the admission of containers with capabilities assigned",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"187",
		 "orgId":"1",
		 "policyName":"CIS-5.2.11 Minimize the admission of Windows HostProcess Containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"187",
		 "variables":"",
		 "conditionName":"CIS-5.2.11 Minimize the admission of Windows HostProcess Containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"188",
		 "orgId":"1",
		 "policyName":"CIS-5.2.12 Minimize the admission of HostPath volumes",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A container which mounts a hostPath volume as part of its specification will have access to the filesystem of the underlying cluster node. The use of hostPath volumes may allow containers access to privileged areas of the node filesystem. There should be at least one admission control policy defined which does not permit containers to mount hostPath volumes. If you need to run containers which require hostPath volumes, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"188",
		 "variables":"",
		 "conditionName":"CIS-5.2.12 Minimize the admission of HostPath volumes",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"189",
		 "orgId":"1",
		 "policyName":"CIS-5.2.13 Minimize the admission of containers which use HostPorts",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Host ports connect containers directly to the hosts network. This can bypass controls such as network policy. There should be at least one admission control policy defined which does not permit containers which require the use of HostPorts. If you need to run containers which require HostPorts, this should be defined in a separate policy and you should carefully check to ensure that only limited service accounts and users are given permission to use that policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"189",
		 "variables":"",
		 "conditionName":"CIS-5.2.13 Minimize the admission of containers which use HostPorts",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"190",
		 "orgId":"1",
		 "policyName":"CIS-5.3.1 Ensure that the CNI in use supports Network Policies",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes network policies are enforced by the CNI plugin in use. As such it is important to ensure that the CNI plugin supports both Ingress and Egress network policies.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"190",
		 "variables":"",
		 "conditionName":"CIS-5.3.1 Ensure that the CNI in use supports Network Policies",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"191",
		 "orgId":"1",
		 "policyName":"CIS-5.3.2 Ensure that all Namespaces have Network Policies defined",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Running different applications on the same Kubernetes cluster creates a risk of one compromised application attacking a neighboring application. Network segmentation is important to ensure that containers can communicate only with those they are supposed to. A network policy is a specification of how selections of pods are allowed to communicate with each other and other network endpoints. Network Policies are namespace scoped. When a network policy is introduced to a given namespace, all traffic not allowed by the policy is denied. However, if there are no network policies in a namespace all traffic will be allowed into and out of the pods in that namespace.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"191",
		 "variables":"",
		 "conditionName":"CIS-5.3.2 Ensure that all Namespaces have Network Policies defined",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"192",
		 "orgId":"1",
		 "policyName":"CIS-5.4.1 Prefer using secrets as files over secrets as environment variables",
		 "category":"System",
		 "stage":"deploy",
		 "description":"It is reasonably common for application code to log out its environment ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"192",
		 "variables":"",
		 "conditionName":"CIS-5.4.1 Prefer using secrets as files over secrets as environment variables",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"193",
		 "orgId":"1",
		 "policyName":"CIS-5.4.2 Consider external secret storage",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes supports secrets as first-class objects, but care needs to be taken to ensure that access to secrets is carefully limited. Using an external secrets provider can ease the management of access to secrets, especially where secrets are used across both Kubernetes and non-Kubernetes environments.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"193",
		 "variables":"",
		 "conditionName":"CIS-5.4.2 Consider external secret storage",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"194",
		 "orgId":"1",
		 "policyName":"CIS-5.7.1 Create administrative boundaries between resources using namespaces",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. A Kubernetes namespace allows you to partition created resources into logically named groups. Resources created in one namespace can be hidden from other namespaces. By default, each resource created by a user in Kubernetes cluster runs in a default namespace, called default. You can create additional namespaces and attach resources and users to them. You can use Kubernetes Authorization plugins to create policies that segregate access to namespace resources between different users.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"194",
		 "variables":"",
		 "conditionName":"CIS-5.7.1 Create administrative boundaries between resources using namespaces",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"195",
		 "orgId":"1",
		 "policyName":"CIS-5.7.2 Ensure that the seccomp profile is set to docker/default in your pod definitions",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Seccomp ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"195",
		 "variables":"",
		 "conditionName":"CIS-5.7.2 Ensure that the seccomp profile is set to docker/default in your pod definitions",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"196",
		 "orgId":"1",
		 "policyName":"CIS-5.7.3 Apply Security Context to Your Pods and Containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A security context defines the operating system security settings ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"196",
		 "variables":"",
		 "conditionName":"CIS-5.7.3 Apply Security Context to Your Pods and Containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"197",
		 "orgId":"1",
		 "policyName":"CIS-5.7.4 The default namespace should not be used",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Resources in a Kubernetes cluster should be segregated by namespace, to allow for security controls to be applied at that level and to make it easier to manage resources.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"197",
		 "variables":"",
		 "conditionName":"CIS-5.7.4 The default namespace should not be used",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"198",
		 "orgId":"1",
		 "policyName":"C-0002 - MITRE - Exec into container",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers who have permissions, can run malicious commands in containers in the cluster using exec command. In this method, attackers can use legitimate images, such as an OS image as a backdoor container, and run their malicious code remotely by using kubectl exec.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"198",
		 "variables":"",
		 "conditionName":"C-0002 - MITRE - Exec into container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"199",
		 "orgId":"1",
		 "policyName":"C-0007 - MITRE - Data Destruction",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers may attempt to destroy data and resources in the cluster. This includes deleting deployments, configurations, storage, and compute resources.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"199",
		 "variables":"",
		 "conditionName":"C-0007 - MITRE - Data Destruction",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"200",
		 "orgId":"1",
		 "policyName":"C-0012 - MITRE - Applications credentials in configuration files",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Such behavior is commonly seen in clusters that are monitored by Azure Security Center. Attackers who have access to those configurations, by querying the API server or by accessing those files on the developers endpoint, can steal the stored secrets and use them.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"200",
		 "variables":"",
		 "conditionName":"C-0012 - MITRE - Applications credentials in configuration files",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"201",
		 "orgId":"1",
		 "policyName":"C-0014 - MITRE - Access Kubernetes dashboard",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The Kubernetes dashboard is a web-based UI that is used for monitoring and managing the Kubernetes cluster. The dashboard allows users to perform actions in the cluster using its service account with the permissions that are determined by the binding or cluster-binding for this service account. Attackers who gain access to a container in the cluster, can use its network access to the dashboard pod. Consequently, attackers may retrieve information about the various resources in the cluster using the dashboards identity.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"201",
		 "variables":"",
		 "conditionName":"C-0014 - MITRE - Access Kubernetes dashboard",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"202",
		 "orgId":"1",
		 "policyName":"C-0015 - MITRE - List Kubernetes secrets",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Secrets can be consumed by reference in the pod configuration. Attackers who have permissions to retrieve the secrets from the API server can access sensitive information that might include credentials to various services.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"202",
		 "variables":"",
		 "conditionName":"C-0015 - MITRE - List Kubernetes secrets",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"203",
		 "orgId":"1",
		 "policyName":"C-0020 - MITRE - Mount service principal",
		 "category":"System",
		 "stage":"deploy",
		 "description":"When the cluster is deployed in the cloud, in some cases attackers can leverage their access to a container in the cluster to gain cloud credentials. For example, in AKS each node contains service principal credential.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"203",
		 "variables":"",
		 "conditionName":"C-0020 - MITRE - Mount service principal",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"204",
		 "orgId":"1",
		 "policyName":"C-0021 - MITRE - Exposed sensitive interfaces",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Exposing a sensitive interface to the internet poses a security risk. Some popular frameworks were not intended to be exposed to the internet, and therefore dont require authentication by default. Thus, exposing them to the internet allows unauthenticated access to a sensitive interface which might enable running code or deploying containers in the cluster by a malicious actor. Examples of such interfaces that were seen exploited include Apache NiFi, Kubeflow, Argo Workflows, Weave Scope, and the Kubernetes dashboard.Note, this control is configurable. See below the details.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"204",
		 "variables":"",
		 "conditionName":"C-0021 - MITRE - Exposed sensitive interfaces",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"205",
		 "orgId":"1",
		 "policyName":"C-0026 - MITRE - Kubernetes CronJob",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes Job is a controller that creates one or more pods and ensures that a specified number of them successfully terminate. Kubernetes Job can be used to run containers that perform finite tasks for batch jobs. Kubernetes CronJob is used to schedule Jobs. Attackers may use Kubernetes CronJob for scheduling execution of malicious code that would run as a container in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"205",
		 "variables":"",
		 "conditionName":"C-0026 - MITRE - Kubernetes CronJob",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"206",
		 "orgId":"1",
		 "policyName":"C-0031 - MITRE - Delete Kubernetes events ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes events can be very useful for identifying changes that occur in the cluster. Therefore, attackers may want to delete these events by using kubectl delete events–all in an attempt to avoid detection of their activity in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"206",
		 "variables":"",
		 "conditionName":"C-0031 - MITRE - Delete Kubernetes events ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"207",
		 "orgId":"1",
		 "policyName":"C-0035 - MITRE - Cluster-admin binding ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Role-based access control is a key security feature in Kubernetes. RBAC can restrict the allowed actions of the various identities in the cluster. Cluster-admin is a built-in high privileged role in Kubernetes. Attackers who have permissions to create bindings and cluster-bindings in the cluster can create a binding to the cluster-admin ClusterRole or to other high privileges roles.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"207",
		 "variables":"",
		 "conditionName":"C-0035 - MITRE - Cluster-admin binding ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"208",
		 "orgId":"1",
		 "policyName":"C-0036 - MITRE - Validate Validating admission controller ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers can use validating webhooks to intercept and discover all the resources in the cluster. This control lists all the validating webhook configurations that must be verified.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"208",
		 "variables":"",
		 "conditionName":"C-0036 - MITRE - Validate Validating admission controller ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"209",
		 "orgId":"1",
		 "policyName":"C-0037 - MITRE - CoreDNS poisoning ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"CoreDNS is a modular Domain Name System ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"209",
		 "variables":"",
		 "conditionName":"C-0037 - MITRE - CoreDNS poisoning ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"210",
		 "orgId":"1",
		 "policyName":"C-0039 - MITRE - Validate Mutating admission controller ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers may use mutating webhooks to intercept and modify all the resources in the cluster. This control lists all mutating webhook configurations that must be verified.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"210",
		 "variables":"",
		 "conditionName":"C-0039 - MITRE - Validate Mutating admission controller ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"211",
		 "orgId":"1",
		 "policyName":"C-0042 - MITRE - SSH server running inside container ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"SSH server that is running inside a container may be used by attackers. If attackers gain valid credentials to a container, whether by brute force attempts or by other methods such as phishing, they can use it to get remote access to the container by SSH.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"211",
		 "variables":"",
		 "conditionName":"C-0042 - MITRE - SSH server running inside container ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"212",
		 "orgId":"1",
		 "policyName":"C-0045 - MITRE - Writable hostPath mount ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"hostPath volume mounts a directory or a file from the host to the container. Attackers who have permissions to create a new container in the cluster may create one with a writable hostPath volume and gain persistence on the underlying host. For example, the latter can be achieved by creating a cron job on the host.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"212",
		 "variables":"",
		 "conditionName":"C-0045 - MITRE - Writable hostPath mount ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"213",
		 "orgId":"1",
		 "policyName":"C-0048 - MITRE - HostPath mount ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Mounting host directory to the container can be used by attackers to get access to the underlying host. This control identifies all the pods using hostPath mount.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"213",
		 "variables":"",
		 "conditionName":"C-0048 - MITRE - HostPath mount ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"214",
		 "orgId":"1",
		 "policyName":"C-0052 - MITRE - Instance Metadata API ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Cloud providers provide instance metadata service for retrieving information about the virtual machine, such as network configuration, disks, and SSH public keys. This service is accessible to the VMs via a non-routable IP address that can be accessed from within the VM only. Attackers who gain access to a container, may query the metadata API service for getting information about the underlying node.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"214",
		 "variables":"",
		 "conditionName":"C-0052 - MITRE - Instance Metadata API ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"215",
		 "orgId":"1",
		 "policyName":"C-0053 - MITRE - Access container service account ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Service account ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"215",
		 "variables":"",
		 "conditionName":"C-0053 - MITRE - Access container service account ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"216",
		 "orgId":"1",
		 "policyName":"C-0054 - MITRE - Cluster internal networking ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes networking behavior allows traffic between pods in the cluster as a default behavior. Attackers who gain access to a single container may use it for network reachability to another container in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"216",
		 "variables":"",
		 "conditionName":"C-0054 - MITRE - Cluster internal networking ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"217",
		 "orgId":"1",
		 "policyName":"C-0057 - MITRE - Privileged container ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A privileged container is a container that has all the capabilities of the host machine, which lifts all the limitations regular containers have. Practically, this means that privileged containers can do almost every action that can be performed directly on the host. Attackers who gain access to a privileged container or have permissions to create a new privileged container ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"217",
		 "variables":"",
		 "conditionName":"C-0057 - MITRE - Privileged container ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"218",
		 "orgId":"1",
		 "policyName":"C-0058 - MITRE - CVE-2021-25741 - Using symlink for arbitrary host file system access ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"218",
		 "variables":"",
		 "conditionName":"C-0058 - MITRE - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"219",
		 "orgId":"1",
		 "policyName":"C-0059 - MITRE - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"219",
		 "variables":"",
		 "conditionName":"C-0059 - MITRE - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"220",
		 "orgId":"1",
		 "policyName":"C-0066 - MITRE - Secret/etcd encryption enabled ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a consistent and highly-available key value store used as Kubernetes backing store for all cluster data. All object data in Kubernetes, like secrets, are stored there. This is the reason why it is important to protect the contents of etcd and use its data encryption feature.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"220",
		 "variables":"",
		 "conditionName":"C-0066 - MITRE - Secret/etcd encryption enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"221",
		 "orgId":"1",
		 "policyName":"C-0067 - MITRE - Audit logs enabled ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"221",
		 "variables":"",
		 "conditionName":"C-0067 - MITRE - Audit logs enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"222",
		 "orgId":"1",
		 "policyName":"C-0068 - MITRE - PSP enabled ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Pod Security Policies enable fine-grained authorization of pod creation and updates and it extends authorization beyond RBAC. It is an important to use PSP to control the creation of sensitive pods in your cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"222",
		 "variables":"",
		 "conditionName":"C-0068 - MITRE - PSP enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"223",
		 "orgId":"1",
		 "policyName":"C-0069 - MITRE - Disable anonymous access to Kubelet service ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"By default, requests to the kubelets HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"223",
		 "variables":"",
		 "conditionName":"C-0069 - MITRE - Disable anonymous access to Kubelet service",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"224",
		 "orgId":"1",
		 "policyName":"C-0070 - MITRE - Enforce Kubelet client TLS authentication ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"224",
		 "variables":"",
		 "conditionName":"C-0070 - MITRE - Enforce Kubelet client TLS authentication",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"225",
		 "orgId":"1",
		 "policyName":"C-0002 - NSA - Exec into container",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers who have permissions, can run malicious commands in containers in the cluster using exec command. In this method, attackers can use legitimate images, such as an OS image as a backdoor container, and run their malicious code remotely by using kubectl exec.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"225",
		 "variables":"",
		 "conditionName":"C-0002 - NSA - Exec into container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"226",
		 "orgId":"1",
		 "policyName":"C-0005 - NSA - API server insecure port is enabled",
		 "category":"System",
		 "stage":"deploy",
		 "description":"The control plane is the core of Kubernetes and gives users the ability to view containers, schedule new Pods, read Secrets, and execute commands in the cluster. Therefore, it should be protected. It is recommended to avoid control plane exposure to the Internet or to an untrusted network. The API server runs on ports 6443 and 8080. We recommend to block them in the firewall. Note also that port 8080, when accessed through the local machine, does not require TLS encryption, and the requests bypass authentication and authorization modules.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"226",
		 "variables":"",
		 "conditionName":"C-0005 - NSA - API server insecure port is enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"227",
		 "orgId":"1",
		 "policyName":"C-0009 - NSA - Resource limits",
		 "category":"System",
		 "stage":"deploy",
		 "description":"CPU and memory resources should have a limit set for every container or a namespace to prevent resource exhaustion. This control identifies all the pods without resource limit definitions by checking their yaml definition file as well as their namespace LimitRange objects. It is also recommended to use ResourceQuota object to restrict overall namespace resources, but this is not verified by this control.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"227",
		 "variables":"",
		 "conditionName":"C-0009 - NSA - Resource limits",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"228",
		 "orgId":"1",
		 "policyName":"C-0012 - NSA - Applications credentials in configuration files",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Developers store secrets in the Kubernetes configuration files, such as environment variables in the pod configuration. Such behavior is commonly seen in clusters that are monitored by Azure Security Center. Attackers who have access to those configurations, by querying the API server or by accessing those files on the developers endpoint, can steal the stored secrets and use them.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"228",
		 "variables":"",
		 "conditionName":"C-0012 - NSA - Applications credentials in configuration files",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"229",
		 "orgId":"1",
		 "policyName":"C-0013 - NSA - Non-root containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Container engines allow containers to run applications as a non-root user with non-root group membership. Typically, this non-default setting is configured when the container image is built. . Alternatively, Kubernetes can load containers into a Pod with SecurityContext:runAsUser specifying a non-zero user. While the runAsUser directive effectively forces non-root execution at deployment, NSA and CISA encourage developers to build container applications to execute as a non-root user. Having non-root execution integrated at build time provides better assurance that applications will function correctly without root privileges.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"229",
		 "variables":"",
		 "conditionName":"C-0013 - NSA - Non-root containers",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"230",
		 "orgId":"1",
		 "policyName":"C-0016 - NSA - Allow privilege escalation",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Attackers may gain access to a container and uplift its privilege to enable excessive capabilities.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"230",
		 "variables":"",
		 "conditionName":"C-0016 - NSA - Allow privilege escalation",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"231",
		 "orgId":"1",
		 "policyName":"C-0017 - NSA - Immutable container filesystem",
		 "category":"System",
		 "stage":"deploy",
		 "description":"By default, containers are permitted mostly unrestricted execution within their own context. An attacker who has access to a container, can create files and download scripts as he wishes, and modify the underlying application running on the container.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"231",
		 "variables":"",
		 "conditionName":"C-0017 - NSA - Immutable container filesystem",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"232",
		 "orgId":"1",
		 "policyName":"C-0030 - NSA - Ingress and Egress blocked",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Network policies control traffic flow between Pods, namespaces, and external IP addresses. By default, no network policies are applied to Pods or namespaces, resulting in unrestricted ingress and egress traffic within the Pod network. Pods become isolated through a network policy that applies to the Pod or the Pods namespace. Once a Pod is selected in a network policy, it rejects any connections that are not specifically allowed by any applicable policy object.Administrators should use a default policy selecting all Pods to deny all ingress and egress traffic and ensure any unselected Pods are isolated. Additional policies could then relax these restrictions for permissible connections.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"232",
		 "variables":"",
		 "conditionName":"C-0030 - NSA - Ingress and Egress blocked",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"233",
		 "orgId":"1",
		 "policyName":"C-0034 - NSA - Automatic mapping of service account",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Check all service accounts on which automount is not disabled. Check all workloads on which they and their service account dont disable automount.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"233",
		 "variables":"",
		 "conditionName":"C-0034 - NSA - Automatic mapping of service account",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"234",
		 "orgId":"1",
		 "policyName":"C-0035 - NSA - Cluster-admin binding",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Role-based access control ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"234",
		 "variables":"",
		 "conditionName":"C-0035 - NSA - Cluster-admin binding",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"235",
		 "orgId":"1",
		 "policyName":"C-0038 - NSA - Host PID/IPC privileges",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Containers should be isolated from the host machine as much as possible. The hostPID and hostIPC fields in deployment yaml may allow cross-container influence and may expose the host itself to potentially malicious or destructive actions. This control identifies all pods using hostPID or hostIPC privileges.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"235",
		 "variables":"",
		 "conditionName":"C-0038 - NSA - Host PID/IPC privileges",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"236",
		 "orgId":"1",
		 "policyName":"C-0041 - NSA - HostNetwork access",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Potential attackers may gain access to a pod and inherit access to the entire host network. For example, in AWS case, they will have access to the entire VPC. This control identifies all the pods with host network access enabled.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"236",
		 "variables":"",
		 "conditionName":"C-0041 - NSA - HostNetwork access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"237",
		 "orgId":"1",
		 "policyName":"C-0044 - NSA - Container hostPort",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Workloads that contain a container with hostport. The problem that arises is that if the scale of your workload is larger than the number of nodes in your Kubernetes cluster, the deployment fails. And any two workloads that specify the same HostPort cannot be deployed to the same node. In addition, if the host where your pods are running becomes unavailable, Kubernetes reschedules the pods to different nodes. Thus, if the IP address for your workload changes, external clients of your application will lose access to the pod. The same thing happens when you restart your pods — Kubernetes reschedules them to a different node if available.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"237",
		 "variables":"",
		 "conditionName":"C-0044 - NSA - Container hostPort",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"238",
		 "orgId":"1",
		 "policyName":"C-0046 - NSA - Insecure capabilities",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Giving insecure and unnecessary capabilities for a container can increase the impact of a container compromise.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"238",
		 "variables":"",
		 "conditionName":"C-0046 - NSA - Insecure capabilities",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"239",
		 "orgId":"1",
		 "policyName":"C-0054 - NSA - Cluster internal networking",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubernetes networking behavior allows traffic between pods in the cluster as a default behavior. Attackers who gain access to a single container may use it for network reachability to another container in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"239",
		 "variables":"",
		 "conditionName":"C-0054 - NSA - Cluster internal networking",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"240",
		 "orgId":"1",
		 "policyName":"C-0055 - NSA - Linux hardening",
		 "category":"System",
		 "stage":"deploy",
		 "description":"In order to reduce the attack surface, it is recommend, when it is possible, to harden your application using security services such as SELinux, AppArmor, and seccomp. Starting from Kubernetes version 22, SELinux is enabled by default.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"240",
		 "variables":"",
		 "conditionName":"C-0055 - NSA - Linux hardening",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"241",
		 "orgId":"1",
		 "policyName":"C-0057 - NSA - Privileged container",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A privileged container is a container that has all the capabilities of the host machine, which lifts all the limitations regular containers have. Practically, this means that privileged containers can do almost every action that can be performed directly on the host. Attackers who gain access to a privileged container or have permissions to create a new privileged container ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"241",
		 "variables":"",
		 "conditionName":"C-0057 - NSA - Privileged container",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"242",
		 "orgId":"1",
		 "policyName":"C-0058 - NSA - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "category":"System",
		 "stage":"deploy",
		 "description":"A user may be able to create a container with subPath or subPathExpr volume mounts to access files & directories anywhere on the host filesystem. Following Kubernetes versions are affected: v1.22.0 - v1.22.1, v1.21.0 - v1.21.4, v1.20.0 - v1.20.10, version v1.19.14 and lower. This control checks the vulnerable versions and the actual usage of the subPath feature in all Pods in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"242",
		 "variables":"",
		 "conditionName":"C-0058 - NSA - CVE-2021-25741 - Using symlink for arbitrary host file system access",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"243",
		 "orgId":"1",
		 "policyName":"C-0059 - NSA - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Security issue in ingress-nginx where a user that can create or update ingress objects can use the custom snippets feature to obtain all secrets in the cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"243",
		 "variables":"",
		 "conditionName":"C-0059 - NSA - CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"244",
		 "orgId":"1",
		 "policyName":"C-0066 - NSA - Secret/etcd encryption enabled",
		 "category":"System",
		 "stage":"deploy",
		 "description":"etcd is a consistent and highly-available key value store used as Kubernetes backing store for all cluster data. All object data in Kubernetes, like secrets, are stored there. This is the reason why it is important to protect the contents of etcd and use its data encryption feature.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"244",
		 "variables":"",
		 "conditionName":"C-0066 - NSA - Secret/etcd encryption enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"245",
		 "orgId":"1",
		 "policyName":"C-0067 - NSA - Audit logs enabled",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Audit logging is an important security feature in Kubernetes, it enables the operator to track requests to the cluster. It is important to use it so the operator has a record of events happened in Kubernetes.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"245",
		 "variables":"",
		 "conditionName":"C-0067 - NSA - Audit logs enabled",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"246",
		 "orgId":"1",
		 "policyName":"C-0068 - NSA - PSP enabled ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Pod Security Policies enable fine-grained authorization of pod creation and updates and it extends authorization beyond RBAC. It is an important to use PSP to control the creation of sensitive pods in your cluster.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"246",
		 "variables":"",
		 "conditionName":"C-0068 - NSA - PSP enabled ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"247",
		 "orgId":"1",
		 "policyName":"C-0069 - NSA - Disable anonymous access to Kubelet service ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"By default, requests to the kubelets HTTPS endpoint that are not rejected by other configured authentication methods are treated as anonymous requests, and given a username of system:anonymous and a group of system:unauthenticated.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"247",
		 "variables":"",
		 "conditionName":"C-0069 - NSA - Disable anonymous access to Kubelet service ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"248",
		 "orgId":"1",
		 "policyName":"C-0070 - NSA - Enforce Kubelet client TLS authentication ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Kubelets are the node level orchestrator in Kubernetes control plane. They are publishing service port 10250 where they accept commands from API server. Operator must make sure that only API server is allowed to submit commands to Kubelet. This is done through client certificate verification, must configure Kubelet with client CA file to use for this purpose.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"248",
		 "variables":"",
		 "conditionName":"C-0070 - NSA - Enforce Kubelet client TLS authentication ",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"249",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 70-85 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"249",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"250",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 50-70 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"250",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"251",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 30-50 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"251",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"252",
		 "orgId":"1",
		 "policyName":"CIS - Compliance Score - Range: 0-30 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall CIS Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"11"}],
		 "scriptId":"252",
		 "variables":"",
		 "conditionName":"CIS - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"253",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 70-85 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"253",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"254",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 50-70 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"254",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"255",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 30-50 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"255",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"256",
		 "orgId":"1",
		 "policyName":"MITRE - Compliance Score - Range: 0-30 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall MITRE Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"12"}],
		 "scriptId":"256",
		 "variables":"",
		 "conditionName":"MITRE - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"257",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 70-85 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 70-85.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"257",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 70-85",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"258",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 50-70 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 50-70.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"258",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 50-70",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"259",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 30-50 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found between 30-50.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"259",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 30-50",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"260",
		 "orgId":"1",
		 "policyName":"NSA - Compliance Score - Range: 0-30 ",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Overall NSA Complaince Score found below 30.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"13"}],
		 "scriptId":"260",
		 "variables":"",
		 "conditionName":"NSA - Compliance Score - Range: 0-30",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"261",
		 "orgId":"1",
		 "policyName":"Auto-merge should be disabled",
		 "category":"System",
		 "stage":"source",
		 "description":"Auto-merge should not be allowed in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"261",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"262",
		 "orgId":"1",
		 "policyName":"Deploy to Production should be preceeded by Judgements Spinnaker",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Deployments to sensitive environments should have a manual review and judgement stage in pipeline requiring someone to approve deployment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"9"}],
		 "scriptId":"262",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"263",
		 "orgId":"1",
		 "policyName":"Open to merge public repositories for code utilities",
		 "category":"System",
		 "stage":"source",
		 "description":"Dependency ",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"263",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"264",
		 "orgId":"1",
		 "policyName":"Approved user for build trigger",
		 "category":"System",
		 "stage":"build",
		 "description":"Only approved users should be allowed to trigger builds.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"4"}],
		 "scriptId":"264",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"265",
		 "orgId":"1",
		 "policyName":"Refrain from running pipelines originating from forked repos",
		 "category":"System",
		 "stage":"source",
		 "description":"Forks of original repositories should not be able to trigger pipelines.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"265",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"266",
		 "orgId":"1",
		 "policyName":"Bot user cannot merge the code",
		 "category":"System",
		 "stage":"source",
		 "description":"Bot users must not be capable of merging any pull requests.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"266",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"267",
		 "orgId":"1",
		 "policyName":"Admin access privilege should be with less than 5 percent users",
		 "category":"System",
		 "stage":"source",
		 "description":"Only 5% of overall set of users must have admin access over code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"267",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"268",
		 "orgId":"1",
		 "policyName":"Inactive users Access restriction policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Users who have been inactive for more than 3 months must not have access to code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"268",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"269",
		 "orgId":"1",
		 "policyName":"Prohibited use of unspecified ",
		 "category":"",
		 "stage":"",
		 "description":"",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"269",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"270",
		 "orgId":"1",
		 "policyName":"Centralized ",
		 "category":"",
		 "stage":"",
		 "description":"",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"1"}],
		 "scriptId":"270",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"271",
		 "orgId":"1",
		 "policyName":"Artifacts should be signed",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Only signed artifact must be allowed for deployment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"5"},{"id":"6"},{"id":"7"}],
		 "scriptId":"271",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"272",
		 "orgId":"1",
		 "policyName":"Untrusted Deployment via Configuration Drift",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Pipeline configuration should be fetched only from trusted sources.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"10"}],
		 "scriptId":"272",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"273",
		 "orgId":"1",
		 "policyName":"Continuously check for known vulnerabilities",
		 "category":"System",
		 "stage":"artifact",
		 "description":"Continuous check for known vulnerabilities must be enabled in SSD.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"21"}],
		 "scriptId":"273",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"274",
		 "orgId":"1",
		 "policyName":"High severity secret detection in code repository",
		 "category":"System",
		 "stage":"source",
		 "description":"High Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"274",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"275",
		 "orgId":"1",
		 "policyName":"Critical severity secret detection in code repository",
		 "category":"System",
		 "stage":"source",
		 "description":"Critical Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"275",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"276",
		 "orgId":"1",
		 "policyName":"Medium severity secret detection in code repository",
		 "category":"System",
		 "stage":"source",
		 "description":"Medium Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"276",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"277",
		 "orgId":"1",
		 "policyName":"Low severity secret detection in code repository",
		 "category":"System",
		 "stage":"source",
		 "description":"Low Severity secrets must not be exposed in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"277",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"278",
		 "orgId":"1",
		 "policyName":"High severity secret detection in containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"High Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"278",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"279",
		 "orgId":"1",
		 "policyName":"Critical severity secret detection in containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Critical Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"279",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"280",
		 "orgId":"1",
		 "policyName":"Medium severity secret detection in containers",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Medium Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"280",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"281",
		 "orgId":"1",
		 "policyName":"Low severity secret detection in containers",
		 "category":"system",
		 "stage":"deploy",
		 "description":"Low Severity secrets must not be exposed in containers.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"16"}],
		 "scriptId":"281",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"282",
		 "orgId":"1",
		 "policyName":"High severity secret detection in helm",
		 "category":"System",
		 "stage":"deploy",
		 "description":"High Severity secrets must not be exposed in helm.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"14"}],
		 "scriptId":"282",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"283",
		 "orgId":"1",
		 "policyName":"Critical severity secret detection in helm",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Critical Severity secrets must not be exposed in helm.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"14"}],
		 "scriptId":"283",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"284",
		 "orgId":"1",
		 "policyName":"Medium severity secret detection in helm",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Medium Severity secrets must not be exposed in helm.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"14"}],
		 "scriptId":"284",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"285",
		 "orgId":"1",
		 "policyName":"Low severity secret detection in helm",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Low Severity secrets must not be exposed in helm.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"14"}],
		 "scriptId":"285",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"286",
		 "orgId":"1",
		 "policyName":"Gitlab Repository Access Control Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Code Repository should not be publicly visible or modifiable.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"286",
		 "variables":"",
		 "conditionName":"Repository Access Control Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"287",
		 "orgId":"1",
		 "policyName":"Gitlab Minimum Reviewers Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Pushed code should be reviewed by a minimum number of users as defined in the policy.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"287",
		 "variables":"",
		 "conditionName":"Minimum Reviewers Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"288",
		 "orgId":"1",
		 "policyName":"Gitlab Branch Protection Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Repositories should have branch protection enabled requiring all code changes to be reviewed. This means disabling Push events and requiring Pull/Merge Requests to have code reviews.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"288",
		 "variables":"",
		 "conditionName":"Branch Protection Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"289",
		 "orgId":"1",
		 "policyName":"Gitlab Bot User should not be a Repo Admin",
		 "category":"System",
		 "stage":"source",
		 "description":"Bot User should not be a Repo Admin.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"289",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"290",
		 "orgId":"1",
		 "policyName":"Gitlab SECURITY.md file should be present",
		 "category":"System",
		 "stage":"source",
		 "description":"SECURITY.md file should be present in code repository.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"290",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"291",
		 "orgId":"1",
		 "policyName":"Gitlab Repository 2FA Policy",
		 "category":"System",
		 "stage":"source",
		 "description":"Repositories should be protected based on 2FA authentication",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"291",
		 "variables":"",
		 "conditionName":"Repository 2FA Policy",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"292",
		 "orgId":"1",
		 "policyName":"Gitlab Build Webhook SSL/TLS Policy",
		 "category":"System",
		 "stage":"build",
		 "description":"Webhooks should use SSL/TLS.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"2"}],
		 "scriptId":"292",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"293",
		 "orgId":"1",
		 "policyName":"Deploy to Production should be preceeded by Judgements Argo",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Deployments to sensitive environments should have a manual review and judgement stage in pipeline requiring someone to approve deployment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"8"}],
		 "scriptId":"293",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
	`
	{
		 "policyId":"294",
		 "orgId":"1",
		 "policyName":"Deploy to Production should be preceeded by Judgements Jenkins",
		 "category":"System",
		 "stage":"deploy",
		 "description":"Deployments to sensitive environments should have a manual review and judgement stage in pipeline requiring someone to approve deployment.",
		 "scheduled_policy":false,
		 "datasourceTool":[{"id":"4"}],
		 "scriptId":"294",
		 "variables":"",
		 "conditionName":"",
		 "suggestion":""
	}
	`,
}

var policyEnforcement = []string{
	`
	{
		 "policyId":"1",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"2",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"2",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"3",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"4",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"5",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"6",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"7",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"LOW",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"8",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"CRITICAL",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"9",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"MEDIUM",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"10",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"11",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"12",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"13",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"14",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"15",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"16",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"17",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"18",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"19",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"20",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"21",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"22",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"23",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"24",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"25",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"26",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"27",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"28",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"29",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"30",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"31",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"32",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"33",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"34",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"35",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"36",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"37",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"38",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"39",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"40",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"41",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"42",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"43",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"2.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"44",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"3.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"45",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"4.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"46",
		 "severity":"Medium",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"47",
		 "severity":"Medium",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"48",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"49",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"50",
		 "severity":"Low",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"51",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"52",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"53",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"54",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"55",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"56",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"57",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"58",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"59",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"60",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"61",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"62",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"63",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"64",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"65",
		 "severity":"Critical",
		 "action":"Prevent",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"66",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"67",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"5.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"68",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"2.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"69",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"3.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"70",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"4.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"71",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"1.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"72",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"2.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"73",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"3.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"74",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"4.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"75",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"1.0",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"76",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"77",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"78",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"79",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"80",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"81",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"82",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"83",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"84",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"85",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"86",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"87",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"88",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"89",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"90",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"91",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"92",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"93",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"94",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"95",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"96",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"97",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"98",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"99",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"100",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"101",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"102",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"103",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"104",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"105",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"106",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"107",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"108",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"109",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"110",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"111",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"112",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"113",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"114",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"115",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"116",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"117",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"118",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"119",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"120",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"121",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"122",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"123",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"124",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"125",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"126",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"127",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"128",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"129",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"130",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"131",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"132",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"133",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"134",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"135",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"136",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"137",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"138",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"139",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"140",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"141",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"142",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"143",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"144",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"145",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"146",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"147",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"148",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"149",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"150",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"151",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"152",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"153",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"154",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"155",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"156",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"157",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"158",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"159",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"160",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"161",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"162",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"163",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"164",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"165",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"166",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"167",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"168",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"169",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"170",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"171",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"172",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"173",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"174",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"175",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"176",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"177",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"178",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"179",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"180",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"181",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"182",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"183",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"184",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"185",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"186",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"187",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"188",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"189",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"190",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"191",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"192",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"193",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"194",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"195",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"196",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"197",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"198",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"199",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"200",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"201",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"202",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"203",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"204",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"205",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"206",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"207",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"208",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"209",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"210",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"211",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"212",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"213",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"214",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"215",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"216",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"217",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"218",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"219",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"220",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"221",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"222",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"223",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"224",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"225",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"226",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"227",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"228",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"229",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"230",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"231",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"232",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"233",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"234",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"235",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"236",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"237",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"238",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"239",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"240",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"241",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"242",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"243",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"244",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"245",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"246",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"247",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"248",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"249",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"70-85",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"250",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"50-70",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"251",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"30-50",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"252",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"0-30",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"253",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"70-85",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"254",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"50-70",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"255",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"30-50",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"256",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"0-30",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"257",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"70-85",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"258",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"50-70",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"259",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"30-50",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"260",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"0-30",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"261",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"262",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"263",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"264",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"265",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"266",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"267",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"268",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"269",
		 "severity":"",
		 "action":"",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"270",
		 "severity":"",
		 "action":"",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"271",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"272",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"273",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"274",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"275",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"276",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"277",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"278",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"279",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"280",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"281",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"282",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"283",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"284",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"285",
		 "severity":"Low",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"286",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"287",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"288",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"289",
		 "severity":"Critical",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"290",
		 "severity":"High",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"291",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"true",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"292",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"293",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
	`
	{
		 "policyId":"294",
		 "severity":"Medium",
		 "action":"Alert",
		 "conditionValue":"",
		 "status":true
	}
	`,
}

var tagPolicy = []string{
	`
	{
		id: "1",
		tagName: "policyCategory",
		tagValue: "Git Posture",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "2",
		tagName: "policyCategory",
		tagValue: "Artifact Integrity",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "3",
		tagName: "policyCategory",
		tagValue: "Build Posture",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "4",
		tagName: "policyCategory",
		tagValue: "OpenSSF Scorecard",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "5",
		tagName: "policyCategory",
		tagValue: "Deployment Config",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "6",
		tagName: "policyCategory",
		tagValue: "Pod Security",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "7",
		tagName: "policyCategory",
		tagValue: "NIST-800-53-CM7",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "8",
		tagName: "policyCategory",
		tagValue: "FedRAMP-CM7",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "9",
		tagName: "policyCategory",
		tagValue: "FedRAMP-RA5",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "10",
		tagName: "policyCategory",
		tagValue: "SAST/DAST",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "11",
		tagName: "policyCategory",
		tagValue: "NIST-800-53-AC6",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "12",
		tagName: "policyCategory",
		tagValue: "Code Security",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "13",
		tagName: "policyCategory",
		tagValue: "FedRAMP-AC6",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "14",
		tagName: "policyCategory",
		tagValue: "CIS-Benchmark",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "15",
		tagName: "policyCategory",
		tagValue: "MITRE-ATT&CK",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "16",
		tagName: "policyCategory",
		tagValue: "NSA-CISA",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "17",
		tagName: "policyCategory",
		tagValue: "NIST-800-53-R5",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "18",
		tagName: "policyCategory",
		tagValue: "User Defined Policies",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "19",
		tagName: "policyCategory",
		tagValue: "OWASP-CICD-Top10",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "20",
		tagName: "policyCategory",
		tagValue: "Secret Scan Trivy",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "21",
		tagName: "policyCategory",
		tagValue: "Helm Scan",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "22",
		tagName: "policyCategory",
		tagValue: "Artifact Scan Trivy",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "23",
		tagName: "policyCategory",
		tagValue: "Vulnerability Analysis",
		tagDescription: "",
		createdBy: "system"
	}
	`,
	`
	{
		id: "24",
		tagName: "policyCategory",
		tagValue: "Gitlab",
		tagDescription: "",
		createdBy: "system"
	}
	`,
}
