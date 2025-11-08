class dnssecurity {

  # 2. Install dnsmasq
  package { 'dnsmasq':
    ensure => installed,
    before => Service['dnsmasq'],
  }

  # 3. Deploy config files
  file { '/etc/dnsmasq.conf':
    ensure => file,
    source => 'puppet:///modules/dnssecurity/dnsmasq.conf',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    notify => Service['dnsmasq'],
  }

  file { '/etc/dnsmasq-blacklist':
    ensure => file,
    source => 'puppet:///modules/dnssecurity/dnsmasq-blacklist',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    notify => Service['dnsmasq'],
  }

  file { '/etc/resolv.conf':
    ensure => file,
    source => 'puppet:///modules/dnssecurity/resolv.conf',
    owner  => 'root',
    group  => 'root',
    mode   => '0777',
  }

    # 1. Disable systemd-resolved
  service { 'systemd-resolved':
    ensure => 'stopped',
    enable => false,
    require => Package['dnsmasq'],
  }

  # 4. Enable and start dnsmasq
  service { 'dnsmasq':
    ensure => running,
    enable => true,
    require => Package['dnsmasq'],
  }

}
