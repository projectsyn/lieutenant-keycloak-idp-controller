local context = std.extVar('context');

{
  clientId: 'cluster_%s' % context.cluster.metadata.name,
  name: '%s (%s)' % [ context.cluster.spec.displayName, context.cluster.metadata.name ],
  rootUrl: 'https://oauth-openshift.apps.%s.dev' % context.cluster.metadata.name,
  redirectUris: [ '/oauth2/callback' ],
  attributes: {
    custom: 'attribute',
  },
}
