package controllers

import (
	"context"

	"github.com/Nerzal/gocloak/v13"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	_ "go.uber.org/mock/gomock"
)

// PartialKeycloakClient is a subset of the gocloak client methods that are used by the controller
//
//go:generate go run go.uber.org/mock/mockgen -destination=./mock/partial_keycloak_client.go -package mock . PartialKeycloakClient
type PartialKeycloakClient interface {
	LoginAdmin(ctx context.Context, username, password, realm string) (*gocloak.JWT, error)
	LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error

	GetClients(ctx context.Context, accessToken, realm string, params gocloak.GetClientsParams) ([]*gocloak.Client, error)
	CreateClient(ctx context.Context, accessToken, realm string, newClient gocloak.Client) (string, error)
	UpdateClient(ctx context.Context, accessToken, realm string, updatedClient gocloak.Client) error
	DeleteClient(ctx context.Context, accessToken, realm, idOfClient string) error

	GetClientRoles(ctx context.Context, accessToken, realm, idOfClient string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	AddClientRolesToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []gocloak.Role) error
	CreateClientRole(ctx context.Context, accessToken, realm, idOfClient string, role gocloak.Role) (string, error)
	DeleteClientRole(ctx context.Context, token, realm, idOfClient, roleName string) error

	GetGroupByPath(ctx context.Context, token, realm, groupPath string) (*gocloak.Group, error)
	GetGroupsByClientRole(ctx context.Context, token, realm, roleName, clientID string) ([]*gocloak.Group, error)
	DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []gocloak.Role) error
}

// VaultPartialAuthClient is a subset of the vault auth methods that are used by the controller
//
//go:generate go run go.uber.org/mock/mockgen -destination=./mock/vault_partial_auth_client.go -package mock . VaultPartialAuthClient
type VaultPartialAuthClient interface {
	KubernetesLogin(ctx context.Context, request schema.KubernetesLoginRequest, options ...vault.RequestOption) (*vault.Response[map[string]interface{}], error)
}

// VaultPartialSecretsClient is a subset of the vault secrets methods that are used by the controller
//
// // Currently generics imports are not correctly resolved in the `vault.Response[]`
// //go:generate go run go.uber.org/mock/mockgen -destination=./mock/vault_partial_secrets_client.go -package mock . VaultPartialSecretsClient
type VaultPartialSecretsClient interface {
	KvV2Read(ctx context.Context, path string, options ...vault.RequestOption) (*vault.Response[schema.KvV2ReadResponse], error)
	KvV2Write(ctx context.Context, path string, request schema.KvV2WriteRequest, options ...vault.RequestOption) (*vault.Response[schema.KvV2WriteResponse], error)
	KvV2Delete(ctx context.Context, path string, options ...vault.RequestOption) (*vault.Response[map[string]interface{}], error)
}
