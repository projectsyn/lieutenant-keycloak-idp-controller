IMG_TAG ?= latest

CURDIR ?= $(shell pwd)
BIN_FILENAME ?= $(CURDIR)/$(PROJECT_ROOT_DIR)/lieutenant-keycloak-idp-controller

# Image URL to use all building/pushing image targets
GHCR_IMG ?= ghcr.io/projectsyn/lieutenant-keycloak-idp-controller:$(IMG_TAG)
