import logging
import re
from xml.dom.minidom import parseString
from autotest.client.shared import utils, error
from virttest import libvirt_vm, virsh, utils_libvirtd, utils_misc


def run(test, params, env):
    """
    Test the command virsh capabilities

    (1) Call virsh capabilities
    (2) Call virsh capabilities with an unexpected option
    (3) Call virsh capabilities with libvirtd service stop
    """
    def compare_capabilities_xml(source):
        dom = parseString(source)
        host = dom.getElementsByTagName('host')[0]
        # check that host has a non-empty UUID tag.
        uuid = host.getElementsByTagName('uuid')[0]
        host_uuid_output = uuid.firstChild.data
        logging.info("Host uuid (capabilities_xml):%s", host_uuid_output)
        if host_uuid_output == "":
            raise error.TestFail("The host uuid in capabilities_xml is none!")

        # check the host arch.
        arch = host.getElementsByTagName('arch')[0]
        host_arch_output = arch.firstChild.data
        logging.info("Host arch (capabilities_xml):%s", host_arch_output)
        cmd_result = utils.run("arch", ignore_status=True)
        if cmp(host_arch_output, cmd_result.stdout.strip()) != 0:
            raise error.TestFail("The host arch in capabilities_xml is wrong!")

        # check the host cpus num.
        cpus = dom.getElementsByTagName('cpus')
        host_cpus = 0
        for cpu in cpus:
            host_cpus += int(cpu.getAttribute('num'))
        logging.info("Host cpus num (capabilities_xml):%s", host_cpus)
        cmd = "less /proc/cpuinfo | grep processor | wc -l"
        cmd_result = utils.run(cmd, ignore_status=True)
        if cmp(host_cpus, int(cmd_result.stdout.strip())) != 0:
            raise error.TestFail("Host cpus num (capabilities_xml) is "
                                 "wrong")

        # check the arch of guest supported.
        try:
            img = utils_misc.find_command("qemu-kvm")
        except ValueError:
            raise error.TestNAError("Cannot find qemu-kvm")
        cmd = img + " --cpu ? | grep qemu"
        cmd_result = utils.run(cmd, ignore_status=True)
        guest_wordsize_array = dom.getElementsByTagName('wordsize')
        length = len(guest_wordsize_array)
        for i in range(length):
            element = guest_wordsize_array[i]
            guest_wordsize = element.firstChild.data
            logging.info("Arch of guest supported (capabilities_xml):%s",
                         guest_wordsize)
            if not re.search(guest_wordsize, cmd_result.stdout.strip()):
                raise error.TestFail("The capabilities_xml gives an extra arch "
                                     "of guest to support!")

        # check the type of hyperviosr.
        guest_domain_type = dom.getElementsByTagName('domain')[0]
        guest_domain_type_output = guest_domain_type.getAttribute('type')
        logging.info("Hypervisor (capabilities_xml):%s",
                     guest_domain_type_output)
        cmd_result = virsh.canonical_uri(ignore_status=True, uri=connect_uri)
        if not re.search(guest_domain_type_output, cmd_result):
            raise error.TestFail("The capabilities_xml gives an different "
                                 "hypervisor")

        # check os_type
        guest_os_type = dom.getElementsByTagName('os_type')[0]
        logging.info("guest os type is %s", guest_os_type)
        if connect_uri == "lxc:///":
            if guest_os_type != "exe":
                raise error.TestFail("The capailities_xml gives wrong guest "
                                     "os_type")

    connect_uri = libvirt_vm.normalize_connect_uri(params.get("connect_uri",
                                                              "default"))

    # Prepare libvirtd service
    if params.has_key("libvirtd"):
        libvirtd = params.get("libvirtd")
        if libvirtd == "off":
            utils_libvirtd.libvirtd_stop()

    # Run test case
    option = params.get("virsh_cap_options")
    try:
        output = virsh.capabilities(option, uri=connect_uri,
                                    ignore_status=False, debug=True)
        status = 0  # good
    except error.CmdError:
        status = 1  # bad
        output = ''

    # Recover libvirtd service start
    if libvirtd == "off":
        utils_libvirtd.libvirtd_start()

    # Check status_error
    status_error = params.get("status_error")
    if status_error == "yes":
        if status == 0:
            if libvirtd == "off":
                raise error.TestFail("Command 'virsh capabilities' succeeded "
                                     "with libvirtd service stopped, incorrect")
            else:
                raise error.TestFail("Command 'virsh capabilities %s' succeeded "
                                     "(incorrect command)" % option)
    elif status_error == "no":
        compare_capabilities_xml(output)
        if status != 0:
            raise error.TestFail("Command 'virsh capabilities %s' failed "
                                 "(correct command)" % option)
