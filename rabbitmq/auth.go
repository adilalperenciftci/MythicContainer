package rabbitmq

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MythicMeta/MythicContainer/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	mythicRabbitMQAuthContextHeader = "mythic-auth-context"
	mythicContainerPrincipalHeader  = "mythic-container-principal"
	mythicContainerTimestampHeader  = "mythic-container-timestamp"
	mythicContainerNonceHeader      = "mythic-container-nonce"
	mythicContainerSignatureHeader  = "mythic-container-signature"
	mythicContainerSignatureVersion = "v1"
	authContextCacheTTL             = 24 * time.Hour
	authContextCacheLimit           = 16384
)

type cachedAuthContext struct {
	Token     string
	Expires   time.Time
	Ambiguous bool
}

var requestAuthContexts = struct {
	sync.RWMutex
	tokens map[string]cachedAuthContext
}{tokens: map[string]cachedAuthContext{}}

func signedPublishing(route string, body []byte, publishing amqp.Publishing) (amqp.Publishing, error) {
	principal := strings.ToLower(strings.TrimSpace(config.MythicConfig.ContainerPrincipal))
	if principal == "" || principal != config.MythicConfig.ContainerPrincipal {
		return publishing, errors.New("MYTHIC_CONTAINER_PRINCIPAL is missing or non-canonical")
	}
	secret, err := hex.DecodeString(config.MythicConfig.ContainerAuthToken)
	if err != nil || len(secret) != sha256.Size {
		return publishing, errors.New("MYTHIC_CONTAINER_AUTH_TOKEN is missing or invalid")
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return publishing, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := time.Now().UTC().Unix()
	bodyHash := sha256.Sum256(body)
	canonical := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%s", mythicContainerSignatureVersion, principal, route, timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	if publishing.Headers == nil {
		publishing.Headers = amqp.Table{}
	}
	publishing.UserId = config.MythicConfig.RabbitmqUser
	publishing.Headers[mythicContainerPrincipalHeader] = principal
	publishing.Headers[mythicContainerTimestampHeader] = timestamp
	publishing.Headers[mythicContainerNonceHeader] = nonce
	publishing.Headers[mythicContainerSignatureHeader] = hex.EncodeToString(mac.Sum(nil))
	authToken, err := authContextForBody(body)
	if err != nil {
		return publishing, err
	}
	if authToken != "" {
		publishing.Headers[mythicRabbitMQAuthContextHeader] = authToken
	}
	return publishing, nil
}

func containerReplyRoutingKey(correlationID string) (string, error) {
	principal := strings.ToLower(strings.TrimSpace(config.MythicConfig.ContainerPrincipal))
	if principal == "" || principal != config.MythicConfig.ContainerPrincipal {
		return "", errors.New("MYTHIC_CONTAINER_PRINCIPAL is missing or non-canonical")
	}
	if correlationID == "" {
		return "", errors.New("RabbitMQ reply correlation ID is empty")
	}
	return principal + ".reply." + correlationID, nil
}

func containerTelemetryRoutingKey(routingKey string) (string, error) {
	principal := strings.ToLower(strings.TrimSpace(config.MythicConfig.ContainerPrincipal))
	if principal == "" || principal != config.MythicConfig.ContainerPrincipal {
		return "", errors.New("MYTHIC_CONTAINER_PRINCIPAL is missing or non-canonical")
	}
	return principal + "." + routingKey, nil
}

func rememberRabbitMQAuthContext(route string, headers amqp.Table, body []byte) {
	if headers == nil {
		return
	}
	value, ok := headers[mythicRabbitMQAuthContextHeader]
	if !ok {
		return
	}
	token, ok := value.(string)
	if !ok || token == "" {
		return
	}
	keys := authContextKeysFromBody(body)
	if len(keys) == 0 {
		return
	}
	requestAuthContexts.Lock()
	now := time.Now().UTC()
	for key, entry := range requestAuthContexts.tokens {
		if !entry.Expires.After(now) {
			delete(requestAuthContexts.tokens, key)
		}
	}
	for _, key := range keys {
		isOperation := strings.HasPrefix(key, "operation_id:")
		if isOperation && route != CONTAINER_ON_START && !strings.HasSuffix(route, "_"+CONTAINER_ON_START) {
			continue
		}
		if existing, ok := requestAuthContexts.tokens[key]; ok && existing.Token != token && !isOperation {
			existing.Ambiguous = true
			existing.Expires = now.Add(authContextCacheTTL)
			requestAuthContexts.tokens[key] = existing
			continue
		}
		if _, exists := requestAuthContexts.tokens[key]; !exists && len(requestAuthContexts.tokens) >= authContextCacheLimit {
			continue
		}
		requestAuthContexts.tokens[key] = cachedAuthContext{Token: token, Expires: now.Add(authContextCacheTTL)}
	}
	requestAuthContexts.Unlock()
}

func authContextForBody(body []byte) (string, error) {
	keys := authContextKeysFromBody(body)
	requestAuthContexts.Lock()
	defer requestAuthContexts.Unlock()
	if token, err := authContextForKeys(keys, false); token != "" || err != nil {
		return token, err
	}
	return authContextForKeys(keys, true)
}

func authContextForKeys(keys []string, operationOnly bool) (string, error) {
	token := ""
	for _, key := range keys {
		isOperation := strings.HasPrefix(key, "operation_id:")
		if isOperation != operationOnly {
			continue
		}
		entry, ok := requestAuthContexts.tokens[key]
		if !ok {
			continue
		}
		if !entry.Expires.After(time.Now().UTC()) {
			delete(requestAuthContexts.tokens, key)
			continue
		}
		if entry.Ambiguous {
			return "", fmt.Errorf("message identifier %s has ambiguous RabbitMQ auth contexts", key)
		}
		candidate := entry.Token
		if token != "" && token != candidate {
			return "", errors.New("message identifiers resolve to different RabbitMQ auth contexts")
		}
		token = candidate
	}
	return token, nil
}

func authContextKeysFromBody(body []byte) []string {
	message := interface{}(nil)
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&message); err != nil {
		return nil
	}
	keys := map[string]struct{}{}
	collectAuthContextKeys(message, "", 0, keys)
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func collectAuthContextKeys(value interface{}, parent string, depth int, result map[string]struct{}) {
	if depth > 6 {
		return
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			normalizedKey := key
			if key == "id" && (parent == "task" || parent == "callback") {
				normalizedKey = parent + "_id"
			}
			if isAuthContextIdentifier(normalizedKey) {
				if identifier := authContextIdentifier(child); identifier != "" {
					result[normalizedKey+":"+identifier] = struct{}{}
				}
			}
			collectAuthContextKeys(child, key, depth+1, result)
		}
	case []interface{}:
		for _, child := range typed {
			collectAuthContextKeys(child, parent, depth+1, result)
		}
	}
}

func isAuthContextIdentifier(key string) bool {
	switch key {
	case "operation_id", "task_id", "callback_id", "agent_callback_id", "eventstepinstance_id", "uuid", "payload_uuid", "build_uuid":
		return true
	default:
		return false
	}
}

func authContextIdentifier(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		if parsed, err := typed.Int64(); err == nil && parsed > 0 {
			return strconv.FormatInt(parsed, 10)
		}
	}
	return ""
}
