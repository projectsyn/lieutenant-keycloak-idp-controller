local context = std.extVar('context');
local client = std.extVar('client');

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
  {
    role: 'zz-foobar',
    group: '%s' % client.name,
  },
]
