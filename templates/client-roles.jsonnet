local context = std.extVar('context');

[
  {
    role: 'openshiftroot',
    group: '/LDAP/VSHN openshiftroot',
  },
  {
    role: 'openshiftrootswissonly',
  },
  {
    // https://github.com/sventorben/keycloak-restrict-client-auth#role-based-mode
    role: 'restricted-access',

    group: '/LDAP_Customers/Service %s' % context.cluster.metadata.name,
  },
]
