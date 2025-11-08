class blacklistmonitor {

  # 1. Deploy Python script
  file { '/usr/local/bin/dns_anomaly_detection.py':
    ensure => file,
    source => 'puppet:///modules/blacklistmonitor/dns_anomaly_detection.py',
    owner  => 'root',
    group  => 'root',
    mode   => '0755',
  }

  # 2. Start the script in background as root (if not already running)
  exec { 'run_dns_blacklist_monitor':
    command => 'nohup /usr/bin/python3 /usr/local/bin/dns_anomaly_detection.py >/var/log/dns_vt_only.log 2>&1 &',
    unless  => 'pgrep -f dns_anomaly_detection.py',
    path    => ['/usr/bin', '/bin'],
  }

}
