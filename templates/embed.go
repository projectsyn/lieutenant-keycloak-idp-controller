package templates

import (
	_ "embed"
)

//go:embed client.jsonnet
var ClientDefault string

//go:embed client-roles.jsonnet
var ClientRolesDefault string
