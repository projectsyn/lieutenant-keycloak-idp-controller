package testtemplates

import (
	_ "embed"
)

//go:embed client.jsonnet
var Client string

//go:embed client-roles.jsonnet
var ClientRoles string
