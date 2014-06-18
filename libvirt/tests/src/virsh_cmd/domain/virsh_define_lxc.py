import os
import logging
import commands
import time
from autotest.client import utils
from autotest.client.shared import error
from virttest.libvirt_xml import vm_xml
from virttest import virsh, aexpect, utils_net
from virttest.libvirt_xml.devices.interface import Interface
from virttest.libvirt_xml.devices.emulator import Emulator
from virttest.libvirt_xml.devices.console import Console
from virttest.libvirt_xml.devices.filesystem import Filesystem


def run(test, params, env):
    """
    Virsh define test with --pass-fds for container
    """
    fds_options = params.get("define_lxc_fds_options", "")
    other_options = params.get("define_lxc_other_options", "")
    uri = params.get("connect_uri", "lxc:///")
    vm_name = params.get("vms")
    vcpu = params.get("define_lxc_vcpu", 1)
    max_mem = params.get("define_lxc_maxmem", 500000)
    cur_mem = params.get("define_lxc_curmem", 500000)
    dom_type = params.get("define_lxc_domtype", "lxc")
    os_type = params.get("define_lxc_ostype", "exe")
    os_arch = params.get("define_lxc_osarch", "x86_64")
    os_init = params.get("define_lxc_osinit", "/bin/sh")
    emulator_path = params.get("define_lxc_emulator",
                               "/usr/libexec/libvirt_lxc")
    undefine = params.get("undefine_domain", "no")
    add_net = ("yes" == params.get("lxc_add_net", "no"))
    interface_type = params.get("lxc_interface_type", "network")
    source_name = params.get("lxc_source_name", "default")
    full_os = ("yes" == params.get("lxc_full_os", "no"))
    repo_file = params.get("lxc_repo_file")
    enable_repo = params.get("lxc_enable_repo")
    install_root = params.get("lxc_install_root", "/")
    fs_target = params.get("lxc_fs_target", "/")
    fs_accessmode = params.get("lxc_fs_accessmode", "passthrough")
    passwd = params.get("lxc_fs_passwd", "redhat")
    operation = params.get("lxc_operation", "define")

    def container_xml_generator():
        """
        Generate container xml
        """
        vmxml = vm_xml.VMXML(dom_type)
        vmxml.vm_name = vm_name
        vmxml.max_mem = max_mem
        vmxml.current_mem = cur_mem
        vmxml.vcpu = vcpu
        vmxml.os_type = os_type
        vmxml.os_arch = os_arch
        vmxml.os_init = os_init
        # Generate emulator
        emulator = Emulator()
        emulator.path = emulator_path
        # Generate console
        console = Console()
        filesystem = Filesystem()
        filesystem.accessmode = fs_accessmode
        filesystem.source = {'dir': install_root}
        filesystem.target = {'dir': fs_target}
        # Add emulator and console in devices
        devices = vm_xml.VMXMLDevices()
        devices.append(emulator)
        devices.append(console)
        devices.append(filesystem)
        # Add network device
        if add_net:
            network = Interface(type_name=interface_type)
            network.mac_address = utils_net.generate_mac_address_simple()
            network.source = {interface_type: source_name}
            devices.append(network)
        logging.debug("device is %s", devices)
        vmxml.set_devices(devices)
        return vmxml

    try:
        vmxml = container_xml_generator()
        logging.debug("xml is %s", commands.getoutput("cat %s" % vmxml.xml))

        if full_os:
            cmd = "yum -y --nogpg --config=%s --installroot=%s --disablerepo" \
                  "='*' --enablerepo=%s install systemd passwd yum redhat-re" \
                  "lease vim-minimal openssh-server procps" % \
                  (repo_file, install_root, enable_repo)
            utils.run(cmd)
            utils.run("echo 'pts/0' >> %s/etc/securetty" % install_root)
            for i in ["session required pam_selinux.so close",
                      "session required pam_loginuid.so"]:
                utils.run("sed -i 's/#%s/%s/g' %s/etc/pam.d/login" %
                          (i, i, install_root))
            session = aexpect.ShellSession("chroot %s /bin/passwd root" %
                                           install_root)
            while True:
                match, text = session.read_until_last_line_matches(
                    [r"New password:", r"Retype new password:"],
                    internal_timeout=1)

                if match == 0 or match == 1:
                    session.sendline(passwd)
                
                if match == 1:
                    break

            session.close()

        if operation == "define":            
            virsh.define(vmxml.xml, uri=uri, ignore_status=False)
            vm = env.get_vm(vm_name)
            if vm.is_persistent():
                logging.info("success to define lxc domain")
            else:
                raise TestFail("fail to define lxc domain")

        elif operation == "create":
            virsh.create(vmxml.xml, uri=uri, ignore_status=False)
            vm = env.get_vm(vm_name)
            if vm.is_alive():
                logging.info("success to create lxc domain")
            else:
                raise TestFail("Fail to create lxc domain")

    finally:
        if undefine == "yes":
            virsh.undefine(vm_name, uri=uri, ignore_status=False)
            if full_os:
                shutil.rmtree(install_root)
