class oracle_java {

    exec{'add_java_repo':
        path     => '/usr/bin',
        command => 'add-apt-repository -y ppa:webupd8team/java && echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo /usr/bin/debconf-set-selections && sudo apt-get update -y',
    }

    exec{'build_java':
        user => root,
        path => [ "/bin/", "/sbin/" , "/usr/bin/", "/usr/sbin/", "/usr/local/sbin/" ],
        command => 'apt-get install -y --force-yes oracle-java8-installer',
        require => Exec['add_java_repo'],
        logoutput => on_failure
    }
  
    package{ 'oracle-java8-jre':
        ensure  => present,
        require => Exec['build_java'],
    }

}