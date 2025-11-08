class kubedns {

  # Stop and disable dnsmasq
  service { 'dnsmasq':
    ensure => 'stopped',
    enable => false,
  }

  # Enable and start systemd-resolved
  service { 'systemd-resolved':
    ensure => 'running',
    enable => true,
    require => Service['dnsmasq'],
  }

  # Replace /etc/resolv.conf with the one from Puppet fileserver
  file { '/etc/resolv.conf':
    ensure  => file,
    source  => 'puppet:///modules/kubedns/resolv.conf',
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Service['systemd-resolved'],
  }

}
