package rabbitmq

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/MythicMeta/MythicContainer/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestSignedPublishingBindsPrincipalRouteAndBody(t *testing.T) {
	oldConfig := config.MythicConfig
	defer func() { config.MythicConfig = oldConfig }()
	secret := sha256.Sum256([]byte("service-secret"))
	config.MythicConfig.ContainerPrincipal = "alpha"
	config.MythicConfig.ContainerAuthToken = hex.EncodeToString(secret[:])
	config.MythicConfig.RabbitmqUser = "mythic_user"
	body := []byte(`{"operation_id":7}`)
	requestAuthContexts.Lock()
	requestAuthContexts.tokens = map[string]cachedAuthContext{
		"operation_id:7": {Token: "mctx_operation", Expires: time.Now().Add(time.Hour)},
	}
	requestAuthContexts.Unlock()

	publishing, err := signedPublishing("route", body, amqp.Publishing{Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if publishing.UserId != "mythic_user" {
		t.Fatalf("user_id = %q", publishing.UserId)
	}
	if publishing.Headers[mythicRabbitMQAuthContextHeader] != "mctx_operation" {
		t.Fatal("operation auth context was not propagated")
	}
	timestamp := publishing.Headers[mythicContainerTimestampHeader].(int64)
	nonce := publishing.Headers[mythicContainerNonceHeader].(string)
	bodyHash := sha256.Sum256(body)
	canonical := "v1\nalpha\nroute\n" + fmt.Sprint(timestamp) + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(canonical))
	if publishing.Headers[mythicContainerSignatureHeader] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not cover canonical request")
	}
}

func TestAuthContextCorrelatesTaskRequestAndResponse(t *testing.T) {
	requestAuthContexts.Lock()
	requestAuthContexts.tokens = map[string]cachedAuthContext{}
	requestAuthContexts.Unlock()
	rememberRabbitMQAuthContext("alpha_payload_build", amqp.Table{mythicRabbitMQAuthContextHeader: "mctx_task"},
		[]byte(`{"task":{"id":42},"callback":{"operation_id":7}}`))

	token, err := authContextForBody([]byte(`{"task_id":42,"success":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if token != "mctx_task" {
		t.Fatalf("task response token = %q, want mctx_task", token)
	}
}

func TestAuthContextCacheRejectsAmbiguousIdentifiers(t *testing.T) {
	requestAuthContexts.Lock()
	requestAuthContexts.tokens = map[string]cachedAuthContext{}
	requestAuthContexts.Unlock()
	body := []byte(`{"task":{"id":42}}`)
	rememberRabbitMQAuthContext("alpha_payload_build", amqp.Table{mythicRabbitMQAuthContextHeader: "mctx_one"}, body)
	rememberRabbitMQAuthContext("alpha_payload_build", amqp.Table{mythicRabbitMQAuthContextHeader: "mctx_two"}, body)
	if _, err := authContextForBody([]byte(`{"task_id":42}`)); err == nil {
		t.Fatal("ambiguous identifier reused an arbitrary auth context")
	}
}

func TestSignedPublishingFailsClosedWithoutIdentity(t *testing.T) {
	oldConfig := config.MythicConfig
	defer func() { config.MythicConfig = oldConfig }()
	config.MythicConfig.ContainerPrincipal = ""
	config.MythicConfig.ContainerAuthToken = ""
	if _, err := signedPublishing("route", []byte(`{}`), amqp.Publishing{}); err == nil {
		t.Fatal("unsigned publishing was accepted")
	}
}
