#!/usr/bin/env python

import datetime
import os
import time

import boto.ec2
from fabric.api import cd, env, execute, local, put, run, sudo
from fabric.colors import green as _green, yellow as _yellow
from fabric.contrib.files import exists
from fabric.network import disconnect_all


#
# Edit env defaults to customize AMI.
#
env.ec2_region = "us-east-1"
env.ec2_amis = ['ami-d05e75b8']  # Ubuntu Server 14.04 LTS (HVM), SSD Volume Type
env.ec2_keypair = 'MinecraftEC2'
env.ec2_secgroups = ['minecraft']
env.ec2_instancetype = 't2.micro'
env.ec2_userdata = open('cloud-config').read()


def _get_instance_status(instance, conn):
    return conn.get_all_instance_status(instance_ids=instance.id)[0]


def test_ssh(hostname):
    import socket
    from contextlib import closing
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.connect((hostname, 22))
        print (_green("Port 22 reachable"))


def launch_instance():
    print(_green("Launching instance of %s..." % env.ec2_amis[0]))
    conn = boto.ec2.connect_to_region(env.ec2_region)
    reservation = conn.run_instances(
        image_id=env.ec2_amis[0],
        key_name=env.ec2_keypair,
        security_groups=env.ec2_secgroups,
        instance_type=env.ec2_instancetype,
        user_data=env.ec2_userdata)
    instance = reservation.instances[0]

    while instance.state == u'pending':
        print(_yellow("Instance state: %s" % instance.state))
        time.sleep(15)
        instance.update()

    while not instance.public_dns_name:
        print(_yellow("Waiting for Public DNS"))
        time.sleep(15)
        instance.update()

    print(_green("Public DNS: %s" % instance.public_dns_name))
    print(_green("Public IP address: %s" % instance.ip_address))
    print(_green("Instance state: %s" % instance.state))
    print(_green("Instance ID: %s" % instance.id))

    print(_green("Waiting for instance to boot..."))

    status = _get_instance_status(instance, conn)
    while not (status.system_status.status == 'ok' and status.instance_status.status == 'ok' and
                       status.system_status.details[u'reachability'] == u'passed'):
        print(_yellow("System Status: {} - Instance Status: {} - Reachability: {}".format(
            status.system_status.status, status.instance_status.status,
            status.system_status.details[u'reachability']
        )))
        time.sleep(15)
        status = _get_instance_status(instance, conn)

    return instance


def get_running_instance():
    """
    This will just get the first running instance it can find
    """
    print(_green("Getting instance of %s..." % env.ec2_amis[0]))
    conn = boto.ec2.connect_to_region(env.ec2_region)
    print(_green("Connection to EC2 established"))
    reservations = conn.get_all_reservations()
    running_instances = [instance for reservation in reservations
                         for instance in reservation.instances
                         if instance.state == u'running']
    if not running_instances:
        raise RuntimeError("No running EC2 instances found.")
    instance = running_instances[0]

    assert (instance.image_id in env.ec2_amis)
    assert (instance.key_name == env.ec2_keypair)
    assert (instance.groups[0].name == env.ec2_secgroups[0])

    print(_green("Public DNS: %s" % instance.public_dns_name))
    print(_green("Public IP address: %s" % instance.ip_address))
    print(_green("Instance state: %s" % instance.state))
    print(_green("Instance ID: %s" % instance.id))

    status = _get_instance_status(instance, conn)
    assert (status.system_status.status == 'ok')
    assert (status.instance_status.status == 'ok')
    assert (status.system_status.details[u'reachability'] == u'passed')

    return instance


def set_host_env(instance):
    env.user = 'ubuntu'
    env.hosts = [instance.public_dns_name]
    env.key_filename = os.path.join(os.path.expanduser("~"), '.ssh', env.ec2_keypair)


def check_instance_availability():
    env.command_timeout = 5
    env.timeout = 5
    while not exists('/var/lib/cloud/instance/boot-finished', use_sudo=False, verbose=True):
        print(_yellow("Waiting for cloud-init to finish running..."))
        time.sleep(15)
    print(_green("Instance is ready."))
    env.timeout = 10
    env.command_timeout = None


def copy_manifests():
    print(_green("Copying puppet manifests..."))
    local('git archive --prefix=puppet-minecraft/ --output=puppet-minecraft.tar.gz HEAD')
    put('puppet-minecraft.tar.gz', '/home/ubuntu')
    with cd('/home/ubuntu'):
        run('tar xzf puppet-minecraft.tar.gz')
    local('rm puppet-minecraft.tar.gz')


def apply_manifests():
    print(_green("Running puppet apply..."))
    sudo("puppet apply -v " +
         "--modulepath=/home/ubuntu/puppet-minecraft/modules " +
         "/home/ubuntu/puppet-minecraft/manifests/base.pp")


def image_name():
    """
    Return image name in format 'Minecraft-Server-XXX',
    where 'XXX' is the version number, which increments by one
    each time the AMI is built.
    """
    conn = boto.ec2.connect_to_region(env.ec2_region)
    images = conn.get_all_images(owners='self')
    prev_versions = [int(i.name.split('-')[-1]) for i in images
                     if i.name.split('-')[0] == 'Minecraft']
    prev_versions.append(0)  # Ensure prev_versions isn't empty
    version = str(max(prev_versions) + 1).zfill(3)
    return "Minecraft-Server-%s" % version


def image_description():
    today = datetime.date.today().isoformat()
    head_sha1 = local('git rev-parse --verify --short HEAD', capture=True)
    return "Built on %s from %s" % (today, head_sha1)


def create_image(instance_id):
    conn = boto.ec2.connect_to_region(env.ec2_region)
    ami_id = conn.create_image(instance_id, image_name(), image_description())
    return ami_id


def check_image_availability(ami_id):
    print(_green("Building AMI..."))
    conn = boto.ec2.connect_to_region(env.ec2_region)
    image = conn.get_image(ami_id)
    while image.state == u'pending':
        print(_yellow("AMI state: %s" % image.state))
        time.sleep(15)
        image.update()
    if image.state == u'available':
        print(_green("AMI is ready."))
        print(_green("AMI ID: %s" % image.id))
        print(_green("AMI Name: %s" % image.name))
        print(_green("AMI Description: %s" % image.description))
    else:
        print(_yellow("AMI state: %s" % image.state))


def terminate_instance(instance_id):
    print(_green("Terminating instance..."))
    conn = boto.ec2.connect_to_region(env.ec2_region)
    results = conn.terminate_instances(instance_ids=[instance_id])
    instance = results[0]
    while instance.state == u'shutting-down':
        print(_yellow("Instance state: %s" % instance.state))
        time.sleep(15)
        instance.update()
    if instance.state == u'terminated':
        print(_green("Instance terminated."))
    else:
        print(_yellow("Instance state: %s" % instance.state))


def main():
    instance = launch_instance()
    #instance = get_running_instance()
    test_ssh(instance.public_dns_name)
    set_host_env(instance)
    execute(check_instance_availability)
    execute(copy_manifests)
    execute(apply_manifests)
    disconnect_all()
    ami_id = create_image(instance.id)
    check_image_availability(ami_id)
    terminate_instance(instance.id)


if __name__ == '__main__':
    main()
