package json

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"k8s-scanner/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

type RuleDefinition struct {
	Version string     `json:"version"`
	Rules   []JSONRule `json:"rules"`
}

type JSONRule struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Standard    string      `json:"standard"`
	Section     string      `json:"section"`
	Severity    string      `json:"severity"`
	Enabled     bool        `json:"enabled"`
	Check       CheckConfig `json:"check"`
	Remediation string      `json:"remediation"`
	References  []string    `json:"references"`
}

type CheckConfig struct {
	Type       string      `json:"type"`
	Conditions []Condition `json:"conditions"`
	Logic      string      `json:"logic"`
}

type Condition struct {
	Field          string      `json:"field"`
	Operator       string      `json:"operator"`
	Value          interface{} `json:"value"`
	ExpectedResult string      `json:"expected_result"`
}

type JSONBasedRule struct {
	rule JSONRule
}

func NewJSONBasedRule(rule JSONRule) *JSONBasedRule {
	return &JSONBasedRule{rule: rule}
}

func (r *JSONBasedRule) ID() string {
	return r.rule.ID
}

func (r *JSONBasedRule) Title() string {
	return r.rule.Title
}

func (r *JSONBasedRule) Description() string {
	return r.rule.Description
}

func (r *JSONBasedRule) Standard() string {
	return r.rule.Standard
}

func (r *JSONBasedRule) Section() string {
	return r.rule.Section
}

func (r *JSONBasedRule) Severity() types.Severity {
	switch r.rule.Severity {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityMedium
	}
}

func (r *JSONBasedRule) Check(ctx context.Context, client interface{}, config *types.Config) ([]types.Finding, error) {
	if !r.rule.Enabled {
		return []types.Finding{}, nil
	}

	var k8sClient *kubernetes.Clientset
	
	// Handle both *kubernetes.Clientset and wrapped client types
	switch c := client.(type) {
	case *kubernetes.Clientset:
		k8sClient = c
	default:
		// Try to extract clientset from wrapped client using reflection
		if clientWithGetter, ok := client.(interface{ GetClientset() *kubernetes.Clientset }); ok {
			k8sClient = clientWithGetter.GetClientset()
		} else {
			return nil, fmt.Errorf("invalid client type: %T", client)
		}
	}

	var findings []types.Finding

	switch r.rule.Check.Type {
	case "pod":
		findings = r.checkPods(ctx, k8sClient, config)
	case "secret":
		findings = r.checkSecrets(ctx, k8sClient, config)
	case "clusterrolebinding":
		findings = r.checkClusterRoleBindings(ctx, k8sClient, config)
	case "clusterrole":
		findings = r.checkClusterRoles(ctx, k8sClient, config)
	case "service":
		findings = r.checkServices(ctx, k8sClient, config)
	case "networkpolicy":
		findings = r.checkNetworkPolicies(ctx, k8sClient, config)
	default:
		return nil, fmt.Errorf("unsupported check type: %s", r.rule.Check.Type)
	}

	return findings, nil
}

func (r *JSONBasedRule) checkPods(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	namespace := config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, pod := range pods.Items {
		result := r.evaluateConditions(&pod)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "Pod",
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) checkSecrets(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	namespace := config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	secrets, err := client.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, secret := range secrets.Items {
		result := r.evaluateConditions(&secret)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "Secret",
				Name:      secret.Name,
				Namespace: secret.Namespace,
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) checkClusterRoleBindings(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	crbs, err := client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, crb := range crbs.Items {
		result := r.evaluateConditions(&crb)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "ClusterRoleBinding",
				Name:      crb.Name,
				Namespace: "",
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) checkClusterRoles(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	crs, err := client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, cr := range crs.Items {
		result := r.evaluateConditions(&cr)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "ClusterRole",
				Name:      cr.Name,
				Namespace: "",
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) checkServices(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	namespace := config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	services, err := client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, service := range services.Items {
		result := r.evaluateConditions(&service)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "Service",
				Name:      service.Name,
				Namespace: service.Namespace,
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) checkNetworkPolicies(ctx context.Context, client *kubernetes.Clientset, config *types.Config) []types.Finding {
	var findings []types.Finding

	namespace := config.Namespace
	if namespace == "" {
		namespace = metav1.NamespaceAll
	}

	networkPolicies, err := client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings
	}

	for _, np := range networkPolicies.Items {
		result := r.evaluateConditions(&np)
		findings = append(findings, types.Finding{
			ID:          r.ID(),
			Title:       r.Title(),
			Description: r.Description(),
			Standard:    r.Standard(),
			Section:     r.Section(),
			Severity:    r.Severity(),
			Status:      result,
			Resource: types.Resource{
				Kind:      "NetworkPolicy",
				Name:      np.Name,
				Namespace: np.Namespace,
			},
			Remediation: r.rule.Remediation,
			References:  r.rule.References,
		})
	}

	return findings
}

func (r *JSONBasedRule) evaluateConditions(resource runtime.Object) types.Status {
	logic := r.rule.Check.Logic
	if logic == "" {
		logic = "and"
	}

	var results []bool
	for _, condition := range r.rule.Check.Conditions {
		result := r.evaluateCondition(resource, condition)
		results = append(results, result)
	}

	var conditionsMet bool
	if logic == "or" {
		conditionsMet = false
		for _, result := range results {
			if result {
				conditionsMet = true
				break
			}
		}
	} else { // "and"
		conditionsMet = true
		for _, result := range results {
			if !result {
				conditionsMet = false
				break
			}
		}
	}

	if conditionsMet {
		return types.StatusPassed
	}
	return types.StatusFailed
}

func (r *JSONBasedRule) evaluateCondition(resource runtime.Object, condition Condition) bool {
	value := r.getFieldValue(resource, condition.Field)
	result := r.compareValues(value, condition.Operator, condition.Value)
	
	// If expected result is "pass", return the result as-is
	// If expected result is "fail", invert the result
	if condition.ExpectedResult == "fail" {
		return !result
	}
	return result
}

func (r *JSONBasedRule) getFieldValue(obj runtime.Object, fieldPath string) interface{} {
	// Convert the object to a map for easier field access
	objBytes, err := json.Marshal(obj)
	if err != nil {
		return nil
	}

	var objMap map[string]interface{}
	if err := json.Unmarshal(objBytes, &objMap); err != nil {
		return nil
	}

	return r.getNestedValue(objMap, fieldPath)
}

func (r *JSONBasedRule) getNestedValue(obj map[string]interface{}, path string) interface{} {
	// Handle array notation like "spec.containers[*].securityContext.privileged"
	if strings.Contains(path, "[*]") {
		return r.getArrayValues(obj, path)
	}

	parts := strings.Split(path, ".")
	current := obj

	for _, part := range parts {
		if current == nil {
			return nil
		}

		if val, ok := current[part]; ok {
			if nextMap, ok := val.(map[string]interface{}); ok {
				current = nextMap
			} else {
				return val
			}
		} else {
			return nil
		}
	}

	return current
}

func (r *JSONBasedRule) getArrayValues(obj map[string]interface{}, path string) []interface{} {
	parts := strings.Split(path, "[*]")
	if len(parts) != 2 {
		return nil
	}

	arrayPath := parts[0]
	fieldPath := strings.TrimPrefix(parts[1], ".")

	// Get the array
	arrayValue := r.getNestedValue(obj, arrayPath)
	if arrayValue == nil {
		return nil
	}

	array, ok := arrayValue.([]interface{})
	if !ok {
		return nil
	}

	var results []interface{}
	for _, item := range array {
		if itemMap, ok := item.(map[string]interface{}); ok {
			if fieldPath == "" {
				results = append(results, itemMap)
			} else {
				fieldValue := r.getNestedValue(itemMap, fieldPath)
				if fieldValue != nil {
					results = append(results, fieldValue)
				}
			}
		}
	}

	return results
}

func (r *JSONBasedRule) compareValues(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "equals":
		return r.isEqual(actual, expected)
	case "not_equals":
		return !r.isEqual(actual, expected)
	case "exists":
		return actual != nil
	case "not_exists":
		return actual == nil
	case "contains":
		return r.contains(actual, expected)
	case "not_contains":
		return !r.contains(actual, expected)
	case "matches":
		return r.matches(actual, expected)
	case "not_matches":
		return !r.matches(actual, expected)
	case "greater_than":
		return r.greaterThan(actual, expected)
	case "less_than":
		return r.lessThan(actual, expected)
	default:
		return false
	}
}

func (r *JSONBasedRule) isEqual(actual, expected interface{}) bool {
	// Handle array comparisons
	if actualArray, ok := actual.([]interface{}); ok {
		for _, item := range actualArray {
			if reflect.DeepEqual(item, expected) {
				return true
			}
		}
		return false
	}
	return reflect.DeepEqual(actual, expected)
}

func (r *JSONBasedRule) contains(actual, expected interface{}) bool {
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	
	// Handle array contains
	if actualArray, ok := actual.([]interface{}); ok {
		for _, item := range actualArray {
			if strings.Contains(fmt.Sprintf("%v", item), expectedStr) {
				return true
			}
		}
		return false
	}
	
	return strings.Contains(actualStr, expectedStr)
}

func (r *JSONBasedRule) matches(actual, expected interface{}) bool {
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)
	
	// Handle array matches
	if actualArray, ok := actual.([]interface{}); ok {
		for _, item := range actualArray {
			if matched, _ := regexp.MatchString(expectedStr, fmt.Sprintf("%v", item)); matched {
				return true
			}
		}
		return false
	}
	
	matched, _ := regexp.MatchString(expectedStr, actualStr)
	return matched
}

func (r *JSONBasedRule) greaterThan(actual, expected interface{}) bool {
	actualFloat, err1 := r.toFloat64(actual)
	expectedFloat, err2 := r.toFloat64(expected)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return actualFloat > expectedFloat
}

func (r *JSONBasedRule) lessThan(actual, expected interface{}) bool {
	actualFloat, err1 := r.toFloat64(actual)
	expectedFloat, err2 := r.toFloat64(expected)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	return actualFloat < expectedFloat
}

func (r *JSONBasedRule) toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

func LoadRulesFromFile(filePath string) ([]types.Rule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %v", filePath, err)
	}

	var ruleDef RuleDefinition
	if err := json.Unmarshal(data, &ruleDef); err != nil {
		return nil, fmt.Errorf("failed to parse rules file %s: %v", filePath, err)
	}

	var rules []types.Rule
	for _, jsonRule := range ruleDef.Rules {
		if jsonRule.Enabled {
			rules = append(rules, NewJSONBasedRule(jsonRule))
		}
	}

	return rules, nil
}

func LoadRulesFromDirectory(dirPath string) ([]types.Rule, error) {
	var allRules []types.Rule

	files, err := filepath.Glob(filepath.Join(dirPath, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob rules directory %s: %v", dirPath, err)
	}

	for _, file := range files {
		rules, err := LoadRulesFromFile(file)
		if err != nil {
			return nil, err
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}