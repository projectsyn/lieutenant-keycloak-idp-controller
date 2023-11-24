// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/projectsyn/lieutenant-keycloak-idp-controller/controllers (interfaces: VaultPartialSecretsClient)
//
// Generated by this command:
//    mockgen -destination=./mock/vault_partial_secrets_client.go -package mock . VaultPartialSecretsClient
// Package mock is a generated GoMock package.
package mock

import (
        context "context"
        vault "github.com/hashicorp/vault-client-go"
        schema "github.com/hashicorp/vault-client-go/schema"
        gomock "go.uber.org/mock/gomock"
        reflect "reflect"
)

// MockVaultPartialSecretsClient is a mock of VaultPartialSecretsClient interface.
type MockVaultPartialSecretsClient struct {
        ctrl     *gomock.Controller
        recorder *MockVaultPartialSecretsClientMockRecorder
}

// MockVaultPartialSecretsClientMockRecorder is the mock recorder for MockVaultPartialSecretsClient.
type MockVaultPartialSecretsClientMockRecorder struct {
        mock *MockVaultPartialSecretsClient
}

// NewMockVaultPartialSecretsClient creates a new mock instance.
func NewMockVaultPartialSecretsClient(ctrl *gomock.Controller) *MockVaultPartialSecretsClient {
        mock := &MockVaultPartialSecretsClient{ctrl: ctrl}
        mock.recorder = &MockVaultPartialSecretsClientMockRecorder{mock}
        return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockVaultPartialSecretsClient) EXPECT() *MockVaultPartialSecretsClientMockRecorder {
        return m.recorder
}

// KvV2Delete mocks base method.
func (m *MockVaultPartialSecretsClient) KvV2Delete(arg0 context.Context, arg1 string, arg2 ...vault.RequestOption) (*vault.Response[map[string]interface {}], error) {
        m.ctrl.T.Helper()
        varargs := []any{arg0, arg1}
        for _, a := range arg2 {
                varargs = append(varargs, a)
        }
        ret := m.ctrl.Call(m, "KvV2Delete", varargs...)
        ret0, _ := ret[0].(*vault.Response[map[string]interface {}])
        ret1, _ := ret[1].(error)
        return ret0, ret1
}

// KvV2Delete indicates an expected call of KvV2Delete.
func (mr *MockVaultPartialSecretsClientMockRecorder) KvV2Delete(arg0, arg1 any, arg2 ...any) *gomock.Call {
        mr.mock.ctrl.T.Helper()
        varargs := append([]any{arg0, arg1}, arg2...)
        return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KvV2Delete", reflect.TypeOf((*MockVaultPartialSecretsClient)(nil).KvV2Delete), varargs...)
}

// KvV2Read mocks base method.
func (m *MockVaultPartialSecretsClient) KvV2Read(arg0 context.Context, arg1 string, arg2 ...vault.RequestOption) (*vault.Response[schema.KvV2ReadResponse], error) {
        m.ctrl.T.Helper()
        varargs := []any{arg0, arg1}
        for _, a := range arg2 {
                varargs = append(varargs, a)
        }
        ret := m.ctrl.Call(m, "KvV2Read", varargs...)
        ret0, _ := ret[0].(*vault.Response[schema.KvV2ReadResponse])
        ret1, _ := ret[1].(error)
        return ret0, ret1
}

// KvV2Read indicates an expected call of KvV2Read.
func (mr *MockVaultPartialSecretsClientMockRecorder) KvV2Read(arg0, arg1 any, arg2 ...any) *gomock.Call {
        mr.mock.ctrl.T.Helper()
        varargs := append([]any{arg0, arg1}, arg2...)
        return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KvV2Read", reflect.TypeOf((*MockVaultPartialSecretsClient)(nil).KvV2Read), varargs...)
}

// KvV2Write mocks base method.
func (m *MockVaultPartialSecretsClient) KvV2Write(arg0 context.Context, arg1 string, arg2 schema.KvV2WriteRequest, arg3 ...vault.RequestOption) (*vault.Response[schema.KvV2WriteResponse], error) {
        m.ctrl.T.Helper()
        varargs := []any{arg0, arg1, arg2}
        for _, a := range arg3 {
                varargs = append(varargs, a)
        }
        ret := m.ctrl.Call(m, "KvV2Write", varargs...)
        ret0, _ := ret[0].(*vault.Response[schema.KvV2WriteResponse])
        ret1, _ := ret[1].(error)
        return ret0, ret1
}

// KvV2Write indicates an expected call of KvV2Write.
func (mr *MockVaultPartialSecretsClientMockRecorder) KvV2Write(arg0, arg1, arg2 any, arg3 ...any) *gomock.Call {
        mr.mock.ctrl.T.Helper()
        varargs := append([]any{arg0, arg1, arg2}, arg3...)
        return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "KvV2Write", reflect.TypeOf((*MockVaultPartialSecretsClient)(nil).KvV2Write), varargs...)
}
