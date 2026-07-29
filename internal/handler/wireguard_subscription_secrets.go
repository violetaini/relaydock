package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"

	"gopkg.in/yaml.v3"
)

const wireGuardSubscriptionSecretPrefix = "arcway-wg-secret:v1:"

var errUnprotectedWireGuardPrivateKey = errors.New("配置包含未加密的 WireGuard 客户端私钥")
var errUntrustedWireGuardSecret = errors.New("配置包含无效的 WireGuard 加密私钥标记")
var errAmbiguousWireGuardSecret = errors.New("WireGuard 私钥锚点同时被非 WireGuard 配置使用")

type yamlEffectiveFieldResolver struct {
	active map[*yaml.Node]bool
}

type yamlEffectiveField struct {
	value   *yaml.Node
	aliases map[*yaml.Node]struct{}
}

// protectWireGuardSubscriptionContent replaces effective WireGuard proxy keys
// with file-scoped authenticated ciphertext before persistence. Caller-supplied
// ciphertext is rejected; allowExisting is reserved for the startup migration.
func protectWireGuardSubscriptionContent(ctx context.Context, repo *storage.TrafficRepository, scope, content string, allowExisting bool) (string, error) {
	if repo == nil {
		return "", errors.New("WireGuard 订阅私钥存储不可用")
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "", errors.New("WireGuard 订阅私钥范围不能为空")
	}
	root, sources, err := wireGuardProxyPrivateKeySources(content)
	if err != nil {
		return "", err
	}
	allMarkers := scalarNodesWithPrefix(root, wireGuardSubscriptionSecretPrefix)
	if !allowExisting && len(allMarkers) > 0 {
		return "", errUntrustedWireGuardSecret
	}
	if err := ensureOnlyEffectiveWireGuardSources(allMarkers, sources); err != nil {
		return "", err
	}
	if len(sources) == 0 {
		if err := ensureNoUnprotectedPrivateKeyFields(root); err != nil {
			return "", err
		}
		return content, nil
	}

	literals := make([]string, 0, len(sources))
	for _, source := range sources {
		value := strings.TrimSpace(source.Value)
		if strings.HasPrefix(value, wireGuardSubscriptionSecretPrefix) {
			if !allowExisting {
				return "", errUntrustedWireGuardSecret
			}
			if _, err := repo.OpenWireGuardSubscriptionPrivateKey(scope, strings.TrimPrefix(value, wireGuardSubscriptionSecretPrefix)); err != nil {
				return "", errUntrustedWireGuardSecret
			}
			continue
		}
		sealed, err := repo.SealWireGuardSubscriptionPrivateKey(scope, value)
		if err != nil {
			return "", err
		}
		literals = append(literals, value)
		source.Value = wireGuardSubscriptionSecretPrefix + sealed
		source.Tag = "!!str"
		source.Kind = yaml.ScalarNode
	}
	if err := ensureNoUnprotectedPrivateKeyFields(root); err != nil {
		return "", err
	}

	protected, err := MarshalYAMLWithIndent(root)
	if err != nil {
		return "", err
	}
	protectedText := string(protected)
	for _, literal := range literals {
		if yamlContainsEquivalentWireGuardKey(root, literal) || yamlTextContainsEquivalentWireGuardKey(protectedText, literal) {
			return "", errors.New("WireGuard 私钥在 YAML 的其他字段或注释中重复，已拒绝落盘")
		}
	}
	if _, verifiedSources, err := wireGuardProxyPrivateKeySources(protectedText); err != nil {
		return "", err
	} else {
		for _, source := range verifiedSources {
			if !strings.HasPrefix(strings.TrimSpace(source.Value), wireGuardSubscriptionSecretPrefix) {
				return "", errUnprotectedWireGuardPrivateKey
			}
		}
	}
	return protectedText, nil
}

// hydrateWireGuardSubscriptionContent decrypts file-scoped snapshots in memory.
// It never follows a mutable node ID, so an old subscription cannot retrieve a
// replacement key after the corresponding node is rotated.
func hydrateWireGuardSubscriptionContent(ctx context.Context, repo *storage.TrafficRepository, scope, content string) (string, error) {
	if repo == nil {
		return "", errors.New("WireGuard 订阅私钥存储不可用")
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "", errors.New("WireGuard 订阅私钥范围不能为空")
	}
	root, sources, err := wireGuardProxyPrivateKeySources(content)
	if err != nil {
		return "", err
	}
	allMarkers := scalarNodesWithPrefix(root, wireGuardSubscriptionSecretPrefix)
	if err := ensureOnlyEffectiveWireGuardSources(allMarkers, sources); err != nil {
		return "", err
	}
	if len(sources) == 0 {
		return content, nil
	}
	changed := false
	for _, source := range sources {
		value := strings.TrimSpace(source.Value)
		if !strings.HasPrefix(value, wireGuardSubscriptionSecretPrefix) {
			return "", errUnprotectedWireGuardPrivateKey
		}
		privateKey, err := repo.OpenWireGuardSubscriptionPrivateKey(scope, strings.TrimPrefix(value, wireGuardSubscriptionSecretPrefix))
		if err != nil {
			return "", errUntrustedWireGuardSecret
		}
		source.Value = privateKey
		source.Tag = "!!str"
		source.Kind = yaml.ScalarNode
		changed = true
	}
	if !changed {
		return content, nil
	}
	hydrated, err := MarshalYAMLWithIndent(root)
	if err != nil {
		return "", err
	}
	return string(hydrated), nil
}

// rebindWireGuardSubscriptionContent authenticates and decrypts a persisted
// payload with its old filename, then immediately seals it for the new
// filename. Plaintext exists only in memory and is never returned to callers.
func rebindWireGuardSubscriptionContent(ctx context.Context, repo *storage.TrafficRepository, oldScope, newScope, content string) (string, error) {
	oldScope = strings.TrimSpace(oldScope)
	newScope = strings.TrimSpace(newScope)
	if oldScope == "" || newScope == "" || oldScope == newScope {
		return "", errors.New("WireGuard 订阅私钥重绑定范围无效")
	}
	hydrated, err := hydrateWireGuardSubscriptionContent(ctx, repo, oldScope, content)
	if err != nil {
		return "", err
	}
	return protectWireGuardSubscriptionContent(ctx, repo, newScope, hydrated, false)
}

func wireGuardProxyPrivateKeySources(content string) (*yaml.Node, []*yaml.Node, error) {
	root, err := decodeSingleYAMLDocument(content)
	if err != nil {
		return nil, nil, err
	}
	if len(root.Content) == 0 {
		return root, nil, nil
	}
	// Decode performs yaml.v3's semantic merge validation while the resolver
	// below keeps the original source nodes needed for safe rewriting.
	var semantic interface{}
	if err := root.Decode(&semantic); err != nil {
		return nil, nil, err
	}
	document := dereferenceYAMLNode(root.Content[0])
	if document == nil || document.Kind != yaml.MappingNode {
		return root, nil, nil
	}
	resolver := &yamlEffectiveFieldResolver{active: make(map[*yaml.Node]bool)}
	proxiesField, found, err := resolver.field(document, "proxies")
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return root, nil, nil
	}
	proxies, proxyListAliases, err := dereferenceYAMLNodeWithAliases(proxiesField.value)
	if err != nil {
		return nil, nil, err
	}
	// Built-in and user rule templates use `proxies: null` as an empty
	// placeholder that is populated when a subscription is generated. It does
	// not contain a client identity and must remain valid persisted policy.
	if proxies != nil && proxies.Kind == yaml.ScalarNode && proxies.Tag == "!!null" {
		return root, nil, nil
	}
	if proxies == nil || proxies.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("proxies 必须是 YAML 列表")
	}
	proxyListAliases = mergeYAMLAliasSets(proxyListAliases, proxiesField.aliases)

	wireGuardSources := make(map[*yaml.Node]struct{})
	nonWireGuardSources := make(map[*yaml.Node]struct{})
	allowedAliases := make(map[*yaml.Node]map[*yaml.Node]struct{})
	for _, item := range proxies.Content {
		mapping := dereferenceYAMLNode(item)
		if mapping == nil || mapping.Kind != yaml.MappingNode {
			return nil, nil, errors.New("proxies 项必须是 YAML 对象")
		}
		protocolField, hasProtocol, err := resolver.field(item, "type")
		if err != nil {
			return nil, nil, err
		}
		if !hasProtocol {
			continue
		}
		protocolScalar, _, err := yamlScalarTargetWithAliases(protocolField.value)
		if err != nil {
			return nil, nil, errors.New("代理 type 必须是字符串")
		}
		privateField, hasPrivateKey, err := resolver.field(item, "privatekey")
		if err != nil {
			return nil, nil, err
		}
		if !hasPrivateKey {
			continue
		}
		privateScalar, privateValueAliases, err := yamlScalarTargetWithAliases(privateField.value)
		if err != nil {
			return nil, nil, errors.New("代理 private-key 必须是字符串")
		}
		protocol := strings.ToLower(strings.TrimSpace(protocolScalar.Value))
		if protocol == "wireguard" || protocol == "wg" {
			wireGuardSources[privateScalar] = struct{}{}
			aliases := mergeYAMLAliasSets(proxyListAliases, privateField.aliases, privateValueAliases)
			allowedAliases[privateScalar] = mergeYAMLAliasSets(allowedAliases[privateScalar], aliases)
		} else {
			nonWireGuardSources[privateScalar] = struct{}{}
		}
	}
	for source := range wireGuardSources {
		if _, shared := nonWireGuardSources[source]; shared {
			return nil, nil, errAmbiguousWireGuardSecret
		}
	}
	if err := ensureWireGuardSourceAliasesAreExclusive(root, wireGuardSources, allowedAliases); err != nil {
		return nil, nil, err
	}
	sources := make([]*yaml.Node, 0, len(wireGuardSources))
	for source := range wireGuardSources {
		sources = append(sources, source)
	}
	return root, sources, nil
}

func decodeSingleYAMLDocument(content string) (*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return &root, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("订阅配置只允许一个 YAML 文档")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &root, nil
}

func (r *yamlEffectiveFieldResolver) field(mappingNode *yaml.Node, normalizedKey string) (yamlEffectiveField, bool, error) {
	mapping, mappingAliases, err := dereferenceYAMLNodeWithAliases(mappingNode)
	if err != nil {
		return yamlEffectiveField{}, false, err
	}
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return yamlEffectiveField{}, false, errors.New("YAML merge 来源必须是对象")
	}
	if r.active[mapping] {
		return yamlEffectiveField{}, false, errors.New("YAML merge/alias 存在循环")
	}
	r.active[mapping] = true
	defer delete(r.active, mapping)

	var explicit *yaml.Node
	var merge *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key, value := mapping.Content[index], mapping.Content[index+1]
		if isYAMLMergeKey(key) {
			if merge != nil {
				return yamlEffectiveField{}, false, errors.New("同一 YAML 对象包含多个 merge 字段")
			}
			merge = value
			continue
		}
		if normalizeWireGuardYAMLKey(key.Value) == normalizedKey {
			if explicit != nil {
				return yamlEffectiveField{}, false, fmt.Errorf("同一 YAML 对象重复定义 %s", normalizedKey)
			}
			explicit = value
		}
	}
	if explicit != nil {
		return yamlEffectiveField{value: explicit, aliases: mappingAliases}, true, nil
	}
	if merge == nil {
		return yamlEffectiveField{}, false, nil
	}
	field, found, err := r.mergedField(merge, normalizedKey)
	if found {
		field.aliases = mergeYAMLAliasSets(mappingAliases, field.aliases)
	}
	return field, found, err
}

func (r *yamlEffectiveFieldResolver) mergedField(candidate *yaml.Node, normalizedKey string) (yamlEffectiveField, bool, error) {
	node, aliases, err := dereferenceYAMLNodeWithAliases(candidate)
	if err != nil {
		return yamlEffectiveField{}, false, err
	}
	if node == nil {
		return yamlEffectiveField{}, false, errors.New("YAML merge 来源为空")
	}
	switch node.Kind {
	case yaml.MappingNode:
		field, found, err := r.field(node, normalizedKey)
		if found {
			field.aliases = mergeYAMLAliasSets(aliases, field.aliases)
		}
		return field, found, err
	case yaml.SequenceNode:
		for _, item := range node.Content {
			field, found, err := r.mergedField(item, normalizedKey)
			if err != nil {
				return yamlEffectiveField{}, false, err
			}
			if found {
				field.aliases = mergeYAMLAliasSets(aliases, field.aliases)
				return field, true, nil
			}
		}
		return yamlEffectiveField{}, false, nil
	default:
		return yamlEffectiveField{}, false, errors.New("YAML merge 必须引用对象或对象列表")
	}
}

func dereferenceYAMLNode(node *yaml.Node) *yaml.Node {
	resolved, _, err := dereferenceYAMLNodeWithAliases(node)
	if err != nil {
		return nil
	}
	return resolved
}

func dereferenceYAMLNodeWithAliases(node *yaml.Node) (*yaml.Node, map[*yaml.Node]struct{}, error) {
	aliases := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode {
		if _, exists := aliases[node]; exists || node.Alias == nil {
			return nil, nil, errors.New("YAML merge/alias 存在循环或无效引用")
		}
		aliases[node] = struct{}{}
		node = node.Alias
	}
	return node, aliases, nil
}

func yamlScalarTargetWithAliases(node *yaml.Node) (*yaml.Node, map[*yaml.Node]struct{}, error) {
	resolved, aliases, err := dereferenceYAMLNodeWithAliases(node)
	if err != nil {
		return nil, nil, err
	}
	if resolved == nil || resolved.Kind != yaml.ScalarNode {
		return nil, nil, errors.New("YAML 值不是标量")
	}
	return resolved, aliases, nil
}

func mergeYAMLAliasSets(sets ...map[*yaml.Node]struct{}) map[*yaml.Node]struct{} {
	merged := make(map[*yaml.Node]struct{})
	for _, set := range sets {
		for alias := range set {
			merged[alias] = struct{}{}
		}
	}
	return merged
}

func ensureWireGuardSourceAliasesAreExclusive(root *yaml.Node, sources map[*yaml.Node]struct{}, allowed map[*yaml.Node]map[*yaml.Node]struct{}) error {
	aliases := collectYAMLAliasNodes(root)
	for _, alias := range aliases {
		for source := range sources {
			references, err := yamlAliasReferencesPrivateKeySource(alias, source)
			if err != nil {
				return err
			}
			if !references {
				continue
			}
			if _, ok := allowed[source][alias]; !ok {
				return errAmbiguousWireGuardSecret
			}
		}
	}
	return nil
}

func collectYAMLAliasNodes(root *yaml.Node) []*yaml.Node {
	var aliases []*yaml.Node
	visited := make(map[*yaml.Node]bool)
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true
		if node.Kind == yaml.AliasNode {
			aliases = append(aliases, node)
			return
		}
		for _, child := range node.Content {
			walk(child)
		}
	}
	walk(root)
	return aliases
}

func yamlAliasReferencesPrivateKeySource(alias, source *yaml.Node) (bool, error) {
	target, _, err := dereferenceYAMLNodeWithAliases(alias)
	if err != nil {
		return false, err
	}
	return yamlNodeReferencesPrivateKeySource(target, source, make(map[*yaml.Node]bool))
}

func yamlNodeReferencesPrivateKeySource(node, source *yaml.Node, visited map[*yaml.Node]bool) (bool, error) {
	resolved, _, err := dereferenceYAMLNodeWithAliases(node)
	if err != nil {
		return false, err
	}
	if resolved == nil || visited[resolved] {
		return false, nil
	}
	visited[resolved] = true
	switch resolved.Kind {
	case yaml.ScalarNode:
		return resolved == source, nil
	case yaml.MappingNode:
		resolver := &yamlEffectiveFieldResolver{active: make(map[*yaml.Node]bool)}
		field, found, err := resolver.field(resolved, "privatekey")
		if err != nil || !found {
			return false, err
		}
		scalar, _, err := yamlScalarTargetWithAliases(field.value)
		return scalar == source, err
	case yaml.SequenceNode:
		for _, child := range resolved.Content {
			references, err := yamlNodeReferencesPrivateKeySource(child, source, visited)
			if err != nil {
				return false, err
			}
			if references {
				return true, nil
			}
		}
	}
	return false, nil
}

func isYAMLMergeKey(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	return node.Value == "<<" && (node.Tag == "!!merge" || node.Tag == "tag:yaml.org,2002:merge")
}

func normalizeWireGuardYAMLKey(value string) string {
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(value)))
}

func scalarNodesWithPrefix(root *yaml.Node, prefix string) map[*yaml.Node]struct{} {
	result := make(map[*yaml.Node]struct{})
	visited := make(map[*yaml.Node]bool)
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil || visited[node] {
			return
		}
		visited[node] = true
		if node.Kind == yaml.ScalarNode && strings.HasPrefix(strings.TrimSpace(node.Value), prefix) {
			result[node] = struct{}{}
		}
		for _, child := range node.Content {
			walk(child)
		}
		if node.Kind == yaml.AliasNode {
			walk(node.Alias)
		}
	}
	walk(root)
	return result
}

func ensureOnlyEffectiveWireGuardSources(markers map[*yaml.Node]struct{}, sources []*yaml.Node) error {
	allowed := make(map[*yaml.Node]struct{}, len(sources))
	for _, source := range sources {
		allowed[source] = struct{}{}
	}
	for marker := range markers {
		if _, ok := allowed[marker]; !ok {
			return errUntrustedWireGuardSecret
		}
	}
	return nil
}

func ensureNoUnprotectedPrivateKeyFields(root *yaml.Node) error {
	visited := make(map[*yaml.Node]bool)
	var walk func(*yaml.Node) error
	walk = func(node *yaml.Node) error {
		if node == nil || visited[node] {
			return nil
		}
		visited[node] = true
		resolved, _, err := dereferenceYAMLNodeWithAliases(node)
		if err != nil {
			return err
		}
		if resolved != nil && resolved.Kind == yaml.MappingNode {
			for index := 0; index+1 < len(resolved.Content); index += 2 {
				key, value := resolved.Content[index], resolved.Content[index+1]
				if normalizeWireGuardYAMLKey(key.Value) != "privatekey" {
					continue
				}
				scalar, _, err := yamlScalarTargetWithAliases(value)
				if err != nil {
					return errors.New("private-key 必须是字符串")
				}
				candidate := strings.TrimSpace(scalar.Value)
				if strings.HasPrefix(candidate, wireGuardSubscriptionSecretPrefix) {
					continue
				}
				if _, err := decodeManagedWireGuardKey(candidate); err == nil {
					return errUnprotectedWireGuardPrivateKey
				}
			}
		}
		for _, child := range node.Content {
			if err := walk(child); err != nil {
				return err
			}
		}
		if node.Kind == yaml.AliasNode {
			return walk(node.Alias)
		}
		return nil
	}
	return walk(root)
}

func yamlContainsEquivalentWireGuardKey(root *yaml.Node, privateKey string) bool {
	visited := make(map[*yaml.Node]bool)
	var found bool
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil || visited[node] || found {
			return
		}
		visited[node] = true
		if node.Kind == yaml.ScalarNode && equalManagedWireGuardKeys(strings.TrimSpace(node.Value), privateKey) {
			found = true
			return
		}
		for _, child := range node.Content {
			walk(child)
		}
		if node.Kind == yaml.AliasNode {
			walk(node.Alias)
		}
	}
	walk(root)
	return found
}

func yamlTextContainsEquivalentWireGuardKey(text, privateKey string) bool {
	if strings.Contains(text, privateKey) {
		return true
	}
	isKeyRune := func(value rune) bool {
		return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
			value >= '0' && value <= '9' || value == '+' || value == '/' ||
			value == '-' || value == '_' || value == '='
	}
	for _, candidate := range strings.FieldsFunc(text, func(value rune) bool { return !isKeyRune(value) }) {
		candidate = strings.TrimSpace(candidate)
		if len(candidate) < 40 || len(candidate) > 64 {
			continue
		}
		if equalManagedWireGuardKeys(candidate, privateKey) {
			return true
		}
	}
	return false
}
