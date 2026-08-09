package handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/violetaini/relaydock/internal/proxyparser/substore"
	"github.com/violetaini/relaydock/internal/storage"
	"gopkg.in/yaml.v3"
)

const proxyProviderContentPath = "/api/proxy-provider/"

type templateProviderUsage struct {
	explicit            map[string]struct{}
	includeAll          bool
	existingDefinitions map[string]struct{}
}

// renderTemplateWithProxyProviders is the single provider-aware V3 rendering
// path. The effective user owns every managed Provider referenced by a
// template; shared/admin templates never silently borrow another tenant's
// upstream subscription.
func renderTemplateWithProxyProviders(
	ctx context.Context,
	repo *storage.TrafficRepository,
	templateContent string,
	proxies []map[string]any,
	effectiveUsername string,
	forceServer bool,
) (string, error) {
	usage, err := inspectTemplateProviderUsage(templateContent)
	if err != nil {
		return "", err
	}
	// Keep legacy templates independent from Provider storage and master_url.
	// This also preserves previews that intentionally render without a user.
	if len(usage.explicit) == 0 && !usage.includeAll {
		result, renderErr := renderTemplateWithoutProxyProviders(templateContent, proxies)
		if renderErr != nil || !forceServer || len(usage.existingDefinitions) == 0 {
			return result, renderErr
		}
		// Cross-owner and non-Mihomo responses must not retain even unused
		// Provider definitions: they may contain durable Authorization headers
		// whose capability would outlive subscription assignment revocation.
		return reconcileProxyProviderDefinitions(result, usage.existingDefinitions, nil)
	}
	if repo == nil {
		return "", errors.New("proxy provider renderer requires repository")
	}
	effectiveUsername = strings.TrimSpace(effectiveUsername)
	if effectiveUsername == "" {
		admin, err := repo.FindActiveAdminUsername(ctx)
		if err != nil {
			return "", fmt.Errorf("resolve provider owner: %w", err)
		}
		effectiveUsername = admin
	}
	if effectiveUsername == "" {
		return "", errors.New("proxy provider owner is unavailable")
	}

	configs, err := repo.ListProxyProviderConfigs(ctx, effectiveUsername)
	if err != nil {
		return "", fmt.Errorf("list proxy providers: %w", err)
	}
	configByName := make(map[string]storage.ProxyProviderConfig, len(configs))
	for _, config := range configs {
		name := strings.TrimSpace(config.Name)
		if name == "" {
			continue
		}
		if _, duplicate := configByName[name]; duplicate {
			return "", fmt.Errorf("provider name %q is duplicated for this user", name)
		}
		configByName[name] = config
	}

	selected := make(map[string]struct{}, len(usage.explicit)+len(configByName))
	for name := range usage.explicit {
		selected[name] = struct{}{}
	}
	if usage.includeAll {
		for name := range configByName {
			selected[name] = struct{}{}
		}
		for name := range usage.existingDefinitions {
			selected[name] = struct{}{}
		}
	}

	serverProviders := make(map[string][]string)
	nativeProviders := make([]string, 0, len(selected))
	managedNativeDefinitions := make(map[string]map[string]any)
	managedNames := make(map[string]struct{}, len(selected))
	providerProxies := make([]map[string]any, 0)
	usedProxyNames := proxyNameSet(proxies)

	selectedNames := make([]string, 0, len(selected))
	for name := range selected {
		selectedNames = append(selectedNames, name)
	}
	sort.Strings(selectedNames)

	for _, name := range selectedNames {
		config, managed := configByName[name]
		if !managed {
			if _, selfContained := usage.existingDefinitions[name]; !selfContained {
				return "", fmt.Errorf("template references unavailable provider %q", name)
			}
			if forceServer {
				return "", fmt.Errorf("provider %q is defined only in the Mihomo template and cannot be expanded for this client", name)
			}
			nativeProviders = append(nativeProviders, name)
			continue
		}
		managedNames[name] = struct{}{}

		if providerType := strings.ToLower(strings.TrimSpace(config.Type)); providerType != "" && providerType != "http" {
			return "", fmt.Errorf("provider %q has unsupported type %q", name, config.Type)
		}
		mode := normalizeProxyProviderMode(config.ProcessMode)
		if mode != "client" && mode != "server" {
			return "", fmt.Errorf("provider %q has invalid process mode %q", name, config.ProcessMode)
		}
		if forceServer {
			mode = "server"
		}
		if mode == "server" {
			subscription, getErr := repo.GetExternalSubscription(ctx, config.ExternalSubscriptionID, effectiveUsername)
			if getErr != nil {
				return "", fmt.Errorf("load source for provider %q: %w", name, getErr)
			}
			nodes, loadErr := resolveProviderNodeSet(&config, &subscription)
			if loadErr != nil {
				return "", fmt.Errorf("materialize provider %q: %w", name, loadErr)
			}
			nodes, nodeNames := namespaceProviderProxies(name, nodes, usedProxyNames)
			if len(nodes) == 0 {
				return "", fmt.Errorf("provider %q has no usable proxies", name)
			}
			serverProviders[name] = nodeNames
			providerProxies = append(providerProxies, nodes...)
			continue
		}

		token, tokenErr := repo.EnsureProxyProviderAccessToken(ctx, config.ID, effectiveUsername)
		if tokenErr != nil {
			return "", fmt.Errorf("initialize access for provider %q: %w", name, tokenErr)
		}
		definition, definitionErr := buildManagedProxyProviderDefinition(ctx, repo, config, token)
		if definitionErr != nil {
			return "", fmt.Errorf("build provider %q: %w", name, definitionErr)
		}
		nativeProviders = append(nativeProviders, name)
		managedNativeDefinitions[name] = definition
	}

	processor := substore.NewTemplateV3ProcessorWithOptions(nil, substore.TemplateV3ProcessorOptions{
		ServerProviders: serverProviders,
		NativeProviders: nativeProviders,
	})
	result, err := processor.ProcessTemplate(templateContent, proxies)
	if err != nil {
		return "", err
	}
	allProxies := make([]map[string]any, 0, len(proxies)+len(providerProxies))
	allProxies = append(allProxies, proxies...)
	allProxies = append(allProxies, providerProxies...)
	result, err = injectProxiesIntoTemplate(result, allProxies)
	if err != nil {
		return "", err
	}
	if forceServer {
		// A mixed template can reference one managed Provider while retaining
		// other, unused definitions with durable credentials. A server-expanded
		// response never needs any Provider definition, so remove them all.
		for name := range usage.existingDefinitions {
			managedNames[name] = struct{}{}
		}
	}
	result, err = reconcileProxyProviderDefinitions(result, managedNames, managedNativeDefinitions)
	if err != nil {
		return "", err
	}
	if err := validateProxyProviderReferences(result); err != nil {
		return "", err
	}
	return result, nil
}

func renderTemplateWithoutProxyProviders(templateContent string, proxies []map[string]any) (string, error) {
	processor := substore.NewTemplateV3ProcessorWithOptions(nil, substore.TemplateV3ProcessorOptions{})
	result, err := processor.ProcessTemplate(templateContent, proxies)
	if err != nil {
		return "", err
	}
	result, err = injectProxiesIntoTemplate(result, proxies)
	if err != nil {
		return "", err
	}
	if err := validateProxyProviderReferences(result); err != nil {
		return "", err
	}
	return result, nil
}

func inspectTemplateProviderUsage(content string) (templateProviderUsage, error) {
	usage := templateProviderUsage{
		explicit:            make(map[string]struct{}),
		existingDefinitions: make(map[string]struct{}),
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return usage, fmt.Errorf("parse provider template: %w", err)
	}
	rootMap := yamlDocumentMapping(&root)
	if rootMap == nil {
		return usage, errors.New("template root must be a mapping")
	}
	if definitions := yamlMappingValue(rootMap, "proxy-providers"); definitions != nil && definitions.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(definitions.Content); i += 2 {
			name := strings.TrimSpace(definitions.Content[i].Value)
			if name != "" {
				usage.existingDefinitions[name] = struct{}{}
			}
		}
	}
	groups := yamlMappingValue(rootMap, "proxy-groups")
	if groups == nil {
		return usage, nil
	}
	if groups.Kind != yaml.SequenceNode {
		return usage, errors.New("template proxy-groups must be a sequence")
	}
	for _, group := range groups.Content {
		if group.Kind != yaml.MappingNode {
			continue
		}
		if yamlBoolValue(group, "include-all-providers") || yamlBoolValue(group, "include-all") {
			usage.includeAll = true
		}
		if sources := yamlMappingValue(group, "proxies"); sources != nil && sources.Kind == yaml.SequenceNode {
			for _, source := range sources.Content {
				if source.Value == substore.ProxyProvidersMarker {
					usage.includeAll = true
				}
			}
		}
		if providers := yamlMappingValue(group, "use"); providers != nil {
			if providers.Kind != yaml.SequenceNode {
				return usage, errors.New("template provider use must be a sequence")
			}
			for _, provider := range providers.Content {
				name := strings.TrimSpace(provider.Value)
				if name != "" {
					usage.explicit[name] = struct{}{}
				}
			}
		}
	}
	return usage, nil
}

func proxyProviderRequiresServerMaterialization(clientType string) bool {
	clientType = strings.ToLower(strings.TrimSpace(clientType))
	return clientType != "" && clientType != "clash" && clientType != "clashmeta"
}

func resolveProviderNodeSet(config *storage.ProxyProviderConfig, subscription *storage.ExternalSubscription) ([]map[string]any, error) {
	if config == nil || subscription == nil {
		return nil, errors.New("provider source is missing")
	}
	body, err := fetchSubscriptionContent(subscription)
	if err != nil {
		return nil, err
	}
	return decodeProviderNodeSet(config, body)
}

func decodeProviderNodeSet(config *storage.ProxyProviderConfig, body []byte) ([]map[string]any, error) {
	if config == nil {
		return nil, errors.New("provider config is missing")
	}
	if typ := strings.ToLower(strings.TrimSpace(config.Type)); typ != "" && typ != "http" {
		return nil, fmt.Errorf("unsupported provider type %q", config.Type)
	}
	if strings.TrimSpace(config.Header) != "" {
		return nil, errors.New("custom provider headers are not supported; configure the upstream User-Agent on the external subscription")
	}
	if strings.TrimSpace(config.Override) != "" {
		return nil, errors.New("raw provider override is not supported")
	}
	if strings.TrimSpace(config.GeoIPFilter) != "" {
		return nil, errors.New("GeoIP provider filtering is not supported in the request path")
	}

	include, err := compileOptionalProviderRegex(config.Filter, "filter")
	if err != nil {
		return nil, err
	}
	exclude, err := compileOptionalProviderRegex(config.ExcludeFilter, "exclude-filter")
	if err != nil {
		return nil, err
	}
	excludeType, err := compileOptionalProviderRegex(config.ExcludeType, "exclude-type")
	if err != nil {
		return nil, err
	}

	limit := proxyProviderContentLimit(config.SizeLimit)
	if len(body) > limit {
		return nil, errors.New("provider response exceeds size limit")
	}
	body, err = preprocessSubscriptionContent(body)
	if err != nil {
		return nil, fmt.Errorf("preprocess subscription: %w", err)
	}
	if len(body) > limit {
		return nil, errors.New("provider response exceeds size limit")
	}
	var root yaml.Node
	if err := yaml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse provider YAML: %w", err)
	}
	sequence := findProxiesNode(&root)
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return nil, errors.New("provider response does not contain a proxies sequence")
	}
	if len(sequence.Content) > maxProxyProviderNodes {
		return nil, errors.New("provider response contains too many proxies")
	}

	proxies := make([]map[string]any, 0, len(sequence.Content))
	for _, node := range sequence.Content {
		if node.Kind != yaml.MappingNode {
			return nil, errors.New("provider response contains an invalid proxy")
		}
		var proxy map[string]any
		if err := node.Decode(&proxy); err != nil {
			return nil, fmt.Errorf("decode provider proxy: %w", err)
		}
		name, _ := proxy["name"].(string)
		proxyType, _ := proxy["type"].(string)
		name = strings.TrimSpace(name)
		if name == "" || strings.TrimSpace(proxyType) == "" {
			return nil, errors.New("provider response contains an invalid proxy")
		}
		if include != nil && !include.MatchString(name) {
			continue
		}
		if exclude != nil && exclude.MatchString(name) {
			continue
		}
		if excludeType != nil && excludeType.MatchString(proxyType) {
			continue
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

func compileOptionalProviderRegex(value, field string) (*regexp.Regexp, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > maxProxyProviderRegexBytes {
		return nil, fmt.Errorf("provider %s is too long", field)
	}
	expression, err := regexp.Compile(value)
	if err != nil {
		return nil, fmt.Errorf("invalid provider %s: %w", field, err)
	}
	return expression, nil
}

func namespaceProviderProxies(providerName string, proxies []map[string]any, used map[string]struct{}) ([]map[string]any, []string) {
	result := make([]map[string]any, 0, len(proxies))
	names := make([]string, 0, len(proxies))
	rename := make(map[string]string, len(proxies))
	for _, proxy := range proxies {
		original, _ := proxy["name"].(string)
		original = strings.TrimSpace(original)
		if original == "" {
			continue
		}
		base := providerName + " / " + original
		candidate := base
		for suffix := 2; ; suffix++ {
			if _, exists := used[candidate]; !exists {
				break
			}
			candidate = base + " #" + strconv.Itoa(suffix)
		}
		used[candidate] = struct{}{}
		if _, exists := rename[original]; !exists {
			rename[original] = candidate
		}
		cloned := make(map[string]any, len(proxy))
		for key, value := range proxy {
			cloned[key] = value
		}
		cloned["name"] = candidate
		result = append(result, cloned)
		names = append(names, candidate)
	}
	for _, proxy := range result {
		if dialer, ok := proxy["dialer-proxy"].(string); ok {
			if rewritten, found := rename[dialer]; found {
				proxy["dialer-proxy"] = rewritten
			}
		}
	}
	return result, names
}

func proxyNameSet(proxies []map[string]any) map[string]struct{} {
	result := make(map[string]struct{}, len(proxies))
	for _, proxy := range proxies {
		if name, ok := proxy["name"].(string); ok && strings.TrimSpace(name) != "" {
			result[name] = struct{}{}
		}
	}
	return result
}

func buildManagedProxyProviderDefinition(ctx context.Context, repo *storage.TrafficRepository, config storage.ProxyProviderConfig, token string) (map[string]any, error) {
	masterURL, err := canonicalProviderMasterURL(ctx, repo)
	if err != nil {
		return nil, err
	}
	definition := map[string]any{
		"type":     "http",
		"url":      masterURL + proxyProviderContentPath + strconv.FormatInt(config.ID, 10),
		"path":     "./proxy_providers/arcway-" + strconv.FormatInt(config.ID, 10) + ".yaml",
		"interval": max(config.Interval, 60),
		"header": map[string]any{
			"Authorization": []any{"Bearer " + token},
		},
	}
	if proxy := strings.TrimSpace(config.Proxy); proxy != "" {
		definition["proxy"] = proxy
	}
	if config.SizeLimit > 0 {
		definition["size-limit"] = min(config.SizeLimit, maxSubscriptionBytes)
	}
	definition["health-check"] = map[string]any{
		"enable":          config.HealthCheckEnabled,
		"url":             strings.TrimSpace(config.HealthCheckURL),
		"interval":        max(config.HealthCheckInterval, 60),
		"timeout":         max(config.HealthCheckTimeout, 1000),
		"lazy":            config.HealthCheckLazy,
		"expected-status": max(config.HealthCheckExpectedStatus, 100),
	}
	return definition, nil
}

func canonicalProviderMasterURL(ctx context.Context, repo *storage.TrafficRepository) (string, error) {
	raw, err := repo.GetSystemSetting(ctx, "master_url")
	if err != nil {
		return "", fmt.Errorf("read master_url: %w", err)
	}
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("master_url must be an absolute public URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && providerURLHostIsLoopback(parsed.Hostname())) {
		return "", errors.New("master_url must use HTTPS")
	}
	return raw, nil
}

func providerURLHostIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func reconcileProxyProviderDefinitions(content string, managedNames map[string]struct{}, nativeDefinitions map[string]map[string]any) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", err
	}
	rootMap := yamlDocumentMapping(&root)
	if rootMap == nil {
		return "", errors.New("rendered template root must be a mapping")
	}
	definitions := yamlMappingValue(rootMap, "proxy-providers")
	if definitions == nil {
		definitions = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		rootMap.Content = append(rootMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxy-providers"}, definitions)
	}
	if definitions.Kind != yaml.MappingNode {
		return "", errors.New("proxy-providers must be a mapping")
	}

	next := make([]*yaml.Node, 0, len(definitions.Content)+len(nativeDefinitions)*2)
	for i := 0; i+1 < len(definitions.Content); i += 2 {
		name := definitions.Content[i].Value
		if _, managed := managedNames[name]; managed {
			continue
		}
		next = append(next, definitions.Content[i], definitions.Content[i+1])
	}
	names := make([]string, 0, len(nativeDefinitions))
	for name := range nativeDefinitions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		next = append(next,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
			mapToYAMLNode(nativeDefinitions[name]),
		)
	}
	definitions.Content = next
	if len(definitions.Content) == 0 {
		removeYAMLMappingKey(rootMap, "proxy-providers")
	}
	return encodeYAMLDocument(&root)
}

func validateProxyProviderReferences(content string) error {
	usage, err := inspectTemplateProviderUsage(content)
	if err != nil {
		return err
	}
	for name := range usage.explicit {
		if _, exists := usage.existingDefinitions[name]; !exists {
			return fmt.Errorf("rendered group references missing proxy-provider %q", name)
		}
	}
	return nil
}

func yamlDocumentMapping(root *yaml.Node) *yaml.Node {
	if root == nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	return root.Content[0]
}

func yamlMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func yamlBoolValue(mapping *yaml.Node, key string) bool {
	value := yamlMappingValue(mapping, key)
	return value != nil && strings.EqualFold(strings.TrimSpace(value.Value), "true")
}

func removeYAMLMappingKey(mapping *yaml.Node, key string) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

func encodeYAMLDocument(root *yaml.Node) (string, error) {
	var output strings.Builder
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return "", err
	}
	return output.String(), nil
}
