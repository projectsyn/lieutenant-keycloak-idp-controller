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
    role: 'restricted-access',
    group: '/LDAP_Customers/Service %s' % context.cluster.metadata.name,
  },
]
