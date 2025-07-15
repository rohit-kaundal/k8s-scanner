package k8s

import (
	"context"
	"fmt"
	"path/filepath"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Client struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
}

func NewClient(kubeconfig string) (*Client, error) {
	config, err := buildConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &Client{
		clientset: clientset,
		config:    config,
	}, nil
}

func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	if _, err := os.Stat(kubeconfig); err != nil {
		return rest.InClusterConfig()
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func (c *Client) GetPods(ctx context.Context, namespace string) (*corev1.PodList, error) {
	return c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetDeployments(ctx context.Context, namespace string) (*appsv1.DeploymentList, error) {
	return c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetDaemonSets(ctx context.Context, namespace string) (*appsv1.DaemonSetList, error) {
	return c.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetServices(ctx context.Context, namespace string) (*corev1.ServiceList, error) {
	return c.clientset.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetConfigMaps(ctx context.Context, namespace string) (*corev1.ConfigMapList, error) {
	return c.clientset.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetSecrets(ctx context.Context, namespace string) (*corev1.SecretList, error) {
	return c.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetServiceAccounts(ctx context.Context, namespace string) (*corev1.ServiceAccountList, error) {
	return c.clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetRoles(ctx context.Context, namespace string) (*rbacv1.RoleList, error) {
	return c.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetClusterRoles(ctx context.Context) (*rbacv1.ClusterRoleList, error) {
	return c.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
}

func (c *Client) GetRoleBindings(ctx context.Context, namespace string) (*rbacv1.RoleBindingList, error) {
	return c.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetClusterRoleBindings(ctx context.Context) (*rbacv1.ClusterRoleBindingList, error) {
	return c.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
}

func (c *Client) GetNetworkPolicies(ctx context.Context, namespace string) (*networkingv1.NetworkPolicyList, error) {
	return c.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
}

func (c *Client) GetPodSecurityPolicies(ctx context.Context) (*policyv1.PodDisruptionBudgetList, error) {
	return c.clientset.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
}

func (c *Client) GetNodes(ctx context.Context) (*corev1.NodeList, error) {
	return c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
}

func (c *Client) GetNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	return c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
}