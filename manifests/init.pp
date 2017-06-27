#### This module is use to enforce some of the vulnerabilities remediations found in apache servers.

class pm_apache {

$package = httpd
$service = httpd
$file_1  = "/etc/httpd/conf/httpd.conf"
$file_2  = "/etc/httpd/conf.d/ssl.conf"
$file_3  = "/home/pemedom1_ms/file.pc"

$file_content = 'one  Peter IS GOOD
two   PETER IS MINE
three PETER IS OUR LEADER'

if $package == "present" {
package { "$package":
  ensure => present,
}
service { "$service":
  ensure => running,
}
}

#if  $file_3 == 'present' {
exec { "echo":
  command => "/bin/echo '$file_content'  >> $file_3",
    onlyif  => "/usr/bin/test -f $file_3",
    }
    }
#
#
#    #class mcelog {
#    #$mce_package = mcelog
#    #
#    #if $mce_package == 'absent' {
#    #  fail("Package is already absent. Unpin node from node group.")
#    #}
#    #
#    #case $::osfamily {
#    #  'Windows':{
#    #    fail("Operating system not supported")
#    #}
# 'RedHat':{
#package { 'mcelog':
#  ensure => 'absent',
