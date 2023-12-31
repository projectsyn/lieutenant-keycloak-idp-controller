local context = std.extVar('context');
local vars = import 'vars.jsonnet';

{
  clientId: '%s%s' % [ vars.clientPrefix, context.cluster.metadata.name ],
  name: '%s (%s)' % [ context.cluster.spec.displayName, context.cluster.metadata.name ],
  description: '',
  rootUrl: 'https://oauth-openshift.apps.%s.dev' % context.cluster.metadata.name,
  adminUrl: '',
  baseUrl: '',
  surrogateAuthRequired: false,
  enabled: true,
  alwaysDisplayInConsole: false,
  clientAuthenticatorType: 'client-secret',
  redirectUris: [
    '/oauth2/callback',
  ],
  webOrigins: [],
  notBefore: 0,
  bearerOnly: false,
  consentRequired: false,
  standardFlowEnabled: true,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: true,
  serviceAccountsEnabled: false,
  publicClient: false,
  frontchannelLogout: true,
  protocol: 'openid-connect',
  attributes: {
    'oidc.ciba.grant.enabled': 'false',
    'backchannel.logout.session.required': 'true',
    'oauth2.device.authorization.grant.enabled': 'false',
    'display.on.consent.screen': 'false',
    'backchannel.logout.revoke.offline.tokens': 'false',
  },
  authenticationFlowBindingOverrides: {},
  fullScopeAllowed: true,
  nodeReRegistrationTimeout: -1,
  defaultClientScopes: [
    'web-origins',
    'acr',
    'profile',
    'roles',
    'email',
  ],
  optionalClientScopes: [
    'address',
    'phone',
    'offline_access',
    'microprofile-jwt',
  ],
  access: {
    view: true,
    configure: true,
    manage: true,
  },
}
