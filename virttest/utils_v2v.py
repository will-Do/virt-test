"""
Virt-v2v test utility functions.

:copyright: 2008-2012 Red Hat Inc.
"""

import os
import re
import time
import logging

import ovirt
import aexpect
from autotest.client import os_dep, utils
from autotest.client.shared import ssh_key
import virsh
import ppm_utils
import data_dir
import remote

import libvirt_vm as lvirt

DEBUG = False

try:
    V2V_EXEC = os_dep.command('virt-v2v')
except ValueError:
    V2V_EXEC = None


class Uri(object):

    """
    This class is used for generating uri.
    """

    def __init__(self, hypervisor):
        if hypervisor is None:
            # kvm is a default hypervisor
            hypervisor = "kvm"
        self.hyper = hypervisor

    def get_uri(self, hostname, vpx_dc=None, esx_ip=None):
        """
        Uri dispatcher.

        :param hostname: String with host name.
        """
        uri_func = getattr(self, "_get_%s_uri" % self.hyper)
        self.host = hostname
        self.vpx_dc = vpx_dc
        self.esx_ip = esx_ip
        return uri_func()

    def _get_kvm_uri(self):
        """
        Return kvm uri.
        """
        uri = "qemu:///system"
        return uri

    def _get_xen_uri(self):
        """
        Return xen uri.
        """
        uri = "xen+ssh://" + self.host + "/"
        return uri

    def _get_esx_uri(self):
        """
        Return esx uri.
        """
        uri = "vpx://root@%s/%s/%s/?no_verify=1" % (self.host,
                                                    self.vpx_dc,
                                                    self.esx_ip)
        return uri

    # add new hypervisor in here.


class Target(object):

    """
    This class is used for generating command options.
    """

    def __init__(self, target, uri):
        if target is None:
            # libvirt is a default target
            target = "libvirt"
        self.tgt = target
        self.uri = uri

    def get_cmd_options(self, params):
        """
        Target dispatcher.
        """
        opts_func = getattr(self, "_get_%s_options" % self.tgt)
        self.params = params
        self.input = self.params.get('input')
        self.files = self.params.get('files')
        self.vm_name = self.params.get('main_vm')
        self.bridge = self.params.get('bridge')
        self.network = self.params.get('network')
        self.storage = self.params.get('storage')
        self.format = self.params.get('output_format', 'raw')
        self.net_vm_opts = ""

        if self.bridge:
            self.net_vm_opts += " -b %s" % self.bridge

        if self.network:
            self.net_vm_opts += " -n %s" % self.network

        self.net_vm_opts += " %s" % self.vm_name

        options = opts_func()

        if self.files is not None:
            # add files as its sequence
            file_list = self.files.split().reverse()
            for file in file_list:
                options = " -f %s %s " % (file, options)
        if self.input is not None:
            options = " -i %s %s" % (self.input, options)
        return options

    def _get_libvirt_options(self):
        """
        Return command options.
        """
        options = " -ic %s -os %s -of %s" % (self.uri,
                                             self.storage,
                                             self.format)
        options = options + self.net_vm_opts

        return options

    def _get_libvirtxml_options(self):
        """
        Return command options.
        """
        options = " -os %s" % self.storage
        options = options + self.net_vm_opts

        return options

    def _get_ovirt_options(self):
        """
        Return command options.
        """
        options = " -ic %s -o rhev -os %s -of %s" % (self.uri,
                                                     self.storage,
                                                     self.format)
        options = options + self.net_vm_opts

        return options

    # add new target in here.


class VirshSessionSASL(virsh.VirshSession):

    """
    A wrap class for virsh session which used SASL infrastructure.
    """
    def __init__(self, params):
        self.virsh_exec = virsh.VIRSH_EXEC
        self.uri = params.get('connect_uri')
        self.sasl_user = params.get('sasl_user')
        self.sasl_pwd = params.get('sasl_pwd')
        self.remote_ip = params.get('remote_ip')
        self.remote_user = params.get('remote_user')
        self.remote_pwd = params.get('remote_pwd')
        self.remote_auth = False
        if self.remote_ip:
            self.remote_auth = True
        super(VirshSessionSASL, self).__init__(virsh_exec=self.virsh_exec,
                                               remote_ip=self.remote_ip,
                                               remote_user=self.remote_user,
                                               remote_pwd=self.remote_pwd,
                                               ssh_remote_auth=self.remote_auth,
                                               auto_close=True,
                                               check_libvirtd=False)
        self.sendline('connect')
        self.sendline(self.sasl_user)
        self.sendline(self.sasl_pwd)
        # make sure session is connected successfully
        if self.cmd_status('list', timeout=60) != 0:
            logging.debug("Persistent virsh session is not responding, "
                          "libvirtd may be dead.")
            raise aexpect.ShellStatusError(virsh.VIRSH_EXEC, 'list')


class VMCheck(object):

    """
    This is VM check class dispatcher.
    """

    def __new__(cls, test, params, env):
        # 'linux' is default os type
        os_type = params.get('os_type', 'linux')

        if cls is VMCheck:
            class_name = eval(os_type.capitalize() + str(cls.__name__))
            return super(VMCheck, cls).__new__(class_name)
        else:
            return super(VMCheck, cls).__new__(cls, test, params, env)

    def __init__(self, test, params, env):
        self.vm = None
        self.test = test
        self.env = env
        self.params = params
        self.name = params.get('main_vm')
        self.os_version = params.get("os_version")
        self.target = params.get('target')
        self.username = params.get('vm_user', 'root')
        self.password = params.get('vm_pwd')
        self.timeout = params.get('timeout', 480)
        self.nic_index = params.get('nic_index', 0)
        self.export_name = params.get('export_name')
        self.delete_vm = 'yes' == params.get('vm_cleanup', 'yes')
        self.virsh_session_id = params.get("virsh_session_id")

        if self.name is None:
            logging.error("vm name not exist")

        # libvirt is a default target
        if self.target == "libvirt" or self.target is None:
            self.vm = lvirt.VM(self.name, self.params, self.test.bindir,
                               self.env.get("address_cache"))
        elif self.target == "ovirt":
            self.vm = ovirt.VMManager(self.params, self.test.bindir,
                                      self.env.get("address_cache"))
        else:
            raise ValueError("Doesn't support %s target now" % self.target)

        # Will create Windows session in WindowsVMCheck.init_boot
        if self.os_type == "linux":
            self.create_session()

    def create_session(self):
        self.session = self.vm.wait_for_login(nic_index=self.nic_index,
                                              timeout=self.timeout,
                                              username=self.username,
                                              password=self.password)
    def vm_cleanup(self):
        """
        Cleanup VM including remove all storage files about guest
        """
        if self.vm.is_alive():
            self.vm.destroy()
            time.sleep(5)
        self.vm.delete()
        if self.target == "ovirt":
            self.vm.delete_from_export_domain(self.export_name)

    def __del__(self):
        """
        Cleanup test environment
        """
        if self.delete_vm:
            self.vm_cleanup()

        if self.session:
            self.session.close()


class LinuxVMCheck(VMCheck):

    """
    This class handles all basic linux VM check operations.
    """

    def get_vm_kernel(self):
        """
        Get vm kernel info.
        """
        cmd = "uname -r"
        kernel_version = self.session.cmd(cmd)
        logging.debug("The kernel of VM '%s' is: %s" %
                      (self.vm.name, kernel_version))
        return kernel_version

    def get_vm_os_info(self):
        """
        Get vm os info.
        """
        cmd = "cat /etc/os-release"
        try:
            output = self.session.cmd(cmd)
            output = output.split('\n')[5].split('=')[1]
        except aexpect.ShellError, e:
            cmd = "cat /etc/issue"
            output = self.session.cmd(cmd).split('\n', 1)[0]
        logging.debug("The os info is: %s" % output)
        return output

    def get_vm_os_vendor(self):
        """
        Get vm os vendor.
        """
        os_info = self.get_vm_os_info()
        if re.search('Red Hat', os_info):
            vendor = 'Red Hat'
        elif re.search('Fedora', os_info):
            vendor = 'Fedora Core'
        elif re.search('SUSE', os_info):
            vendor = 'SUSE'
        elif re.search('Ubuntu', os_info):
            vendor = 'Ubuntu'
        elif re.search('Debian', os_info):
            vendor = 'Debian'
        else:
            vendor = 'Unknown'
        logging.debug("The os vendor of VM '%s' is: %s" %
                      (self.vm.name, vendor))
        return vendor

    def get_vm_parted(self):
        """
        Get vm parted info.
        """
        cmd = "parted -l"
        parted_output = self.session.cmd(cmd)
        logging.debug("The parted output is:\n %s" % parted_output)
        return parted_output

    def get_vm_modprobe_conf(self):
        """
        Get /etc/modprobe.conf info.
        """
        cmd = "cat /etc/modprobe.conf"
        modprobe_output = self.session.cmd(cmd, ok_status=[0, 1])
        logging.debug("modprobe conf is:\n %s" % modprobe_output)
        return modprobe_output

    def get_vm_modules(self):
        """
        Get vm modules list.
        """
        cmd = "lsmod"
        modules = self.session.cmd(cmd)
        logging.debug("VM modules list is:\n %s" % modules)
        return modules

    def get_vm_pci_list(self):
        """
        Get vm pci list.
        """
        cmd = "lspci"
        lspci_output = self.session.cmd(cmd)
        logging.debug("VM pci devices list is:\n %s" % lspci_output)
        return lspci_output

    def get_vm_rc_local(self):
        """
        Get vm /etc/rc.local output.
        """
        cmd = "cat /etc/rc.local"
        rc_output = self.session.cmd(cmd, ok_status=[0, 1])
        return rc_output

    def has_vmware_tools(self):
        """
        Check vmware tools.
        """
        rpm_cmd = "rpm -q VMwareTools"
        ls_cmd = "ls /usr/bin/vmware-uninstall-tools.pl"
        rpm_cmd_status = self.session.cmd_status(rpm_cmd)
        ls_cmd_status = self.session.cmd_status(ls_cmd)

        if (rpm_cmd_status == 0 or ls_cmd_status == 0):
            return True
        else:
            return False

    def get_vm_tty(self):
        """
        Get vm tty config.
        """
        confs = ('/etc/securetty', '/etc/inittab', '/boot/grub/grub.conf',
                 '/etc/default/grub')
        tty = ''
        for conf in confs:
            cmd = "cat " + conf
            tty += self.session.cmd(cmd, ok_status=[0, 1])
        return tty

    def get_vm_video(self):
        """
        Get vm video config.
        """
        cmd = "cat /etc/X11/xorg.conf /etc/X11/XF86Config"
        xorg_output = self.session.cmd(cmd, ok_status=[0, 1])
        return xorg_output

    def is_net_virtio(self):
        """
        Check whether vm's interface is virtio
        """
        cmd = "ls -l /sys/class/net/eth%s/device" % self.nic_index
        driver_output = self.session.cmd(cmd, ok_status=[0, 1])

        if re.search("virtio", driver_output.split('/')[-1]):
            return True
        return False

    def is_disk_virtio(self, disk="/dev/vda"):
        """
        Check whether disk is virtio.
        """
        cmd = "fdisk -l %s" % disk
        disk_output = self.session.cmd(cmd, ok_status=[0, 1])

        if re.search(disk, disk_output):
            return True
        return False


class WindowsVMCheck(VMCheck):

    """
    This class handles all basic Windows VM check operations.
    """

    # Timeout definition for session login.
    LOGIN_TIMEOUT = 480

    def _send_win32_key(self, keycode):
        """
        Send key to Windows VM
        """
        options = "--codeset win32 %s" % keycode
        virsh.sendkey(self.name, options, session_id=self.virsh_session_id)
        time.sleep(1)

    def _move_mouse(self, coordinate):
        """
        Move VM mouse.
        """
        virsh.move_mouse(self.name, coordinate, session_id=self.virsh_session_id)

    def _click_left_button(self):
        """
        Click left button of VM mouse.
        """
        virsh.click_button(self.name, session_id=self.virsh_session_id)

    def _click_tab_enter(self):
        """
        Send TAB and ENTER to VM.
        """
        self._send_win32_key('VK_TAB')
        self._send_win32_key('VK_RETURN')

    def _click_install_driver(self):
        """
        Move mouse and click button to install dirver for new
        device(Ethernet controller)
        """
        # Get window focus by click left button
        self._move_mouse((0, -80))
        self._click_left_button()
        self._move_mouse((0, 30))
        self._click_left_button()

    def _get_screenshot(self):
        """
        Do virsh screenshot of the vm and fetch the image if the VM in
        remote host.
        """
        sshot_file = os.path.join(data_dir.get_tmp_dir(), "vm_screenshot.ppm")
        if self.virsh_session_id:
            vm_sshot = "/tmp/vm_screenshot.ppm"
        else:
            vm_sshot = sshot_file
        virsh.screenshot(self.name, vm_sshot, session_id=self.virsh_session_id)
        if self.virsh_session_id:
            remote_ip = self.params.get("remote_ip")
            remote_user = self.params.get("remote_user")
            remote_pwd = self.params.get("remote_pwd")
            remote.scp_from_remote(remote_ip, '22', remote_user,
                                   remote_pwd, vm_sshot, sshot_file)
        return sshot_file

    def _wait_for_image_match(self, image, similar_degree=0.98,
                              timeout=180):
        """
        Compare VM screenshot with given image, and return true if the
        result is greater than expected smimlar degree.
        """
        end_time = time.time() + timeout
        image_matched = False
        cropped_image = os.path.join(data_dir.get_tmp_dir(), "croped.ppm")
        box = (150, 100, 650, 500)
        ppm_utils.image_crop_save(image, cropped_image, box)
        while time.time() < end_time:
            vm_screenshot = self._get_screenshot()
            ppm_utils.image_crop_save(vm_screenshot, vm_screenshot, box)
            logging.info("Compare vm screenshot with image %s", image)
            h_degree = ppm_utils.image_histogram_compare(cropped_image, vm_screenshot)
            if h_degree >= similar_degree:
                logging.debug("Image %s matched", image)
                image_matched = True
                break
            time.sleep(2)
        if os.path.exists(cropped_image):
            os.unlink(cropped_image)
        if os.path.exists(vm_screenshot):
            os.unlink(vm_screenshot)
        return image_matched

    def init_boot(self):
        """
        Click buttons to let boot progress keep going and install NIC driver.
        """
        image_name = self.params.get("images_for_match")
        match_image = os.path.join(data_dir.get_data_dir(), image_name)
        match_image_timeout = 180
        timeout_msg = "Not match expected image %s in %s seconds,"
        timeout_msg += " so try to login VM directly"
        timeout_msg = timeout_msg % (match_image, match_image_timeout)
        if self.os_version == "win2003":
            if self._wait_for_image_match(match_image,
                                          timeout=match_image_timeout):
                self._click_tab_enter()
            else:
                logging.debug(timeout_msg)
        elif self.os_version in ["win7", "win2008r2"]:
            if self._wait_for_image_match(match_image,
                                          timeout=match_image_timeout):
                self._click_left_button()
                self._click_left_button()
                self._send_win32_key('VK_TAB')
                self._click_tab_enter()
            else:
                logging.debug(timeout_msg)
        elif self.os_version == "win2008":
            if self._wait_for_image_match(match_image,
                                          timeout=match_image_timeout):
                self._click_tab_enter()
                self._click_install_driver()
                self._move_mouse((0, -50))
                self._click_left_button()
                self._click_tab_enter()
            else:
                logging.debug(timeout_msg)
        else:
            # No need sendkey/click button for Win8, Win8.1, Win2012, Win2012r2,
            # so just wait a pediod of time for system boot up.
            logging.info("%s is booting up ...", self.os_version)
            time.sleep(30)
        # Wait 10 seconds for drivers installation
        time.sleep(10)
        self.create_session()

    def get_viostor_info(self):
        """
        Get viostor info.
        """
        cmd = "dir C:\Windows\Drivers\VirtIO\\viostor.sys"
        output = self.session.cmd(cmd)
        logging.debug("The viostor info is: %s" % output)
        return output


    def get_driver_info(self):
        """
        Get windows signed driver info.
        """
        cmd = "DRIVERQUERY /SI"
        output = self.session.cmd(cmd)
        logging.debug("The driver info is: %s" % output)
        return output


    def get_windows_event_info(self):
        """
        Get windows event log info about WSH.
        """
        cmd = "CSCRIPT C:\WINDOWS\system32\eventquery.vbs /l application /Fi \"Source eq WSH\""
        status, output = self.session.cmd_status_output(cmd)
        if status != 0:
            #if the OS version was not win2003 or winXP, use following cmd
            cmd = "wevtutil qe application | find \"WSH\""
            output = self.session.cmd(cmd)
        logging.debug("The windows event log info about WSH is: %s" % output)
        return output


    def get_network_restart(self):
        """
        Get windows network restart.
        """
        cmd = "ipconfig /renew"
        output = self.session.cmd(cmd)
        logging.debug("The windows network restart info is: %s" % output)
        return output


    def copy_windows_file(self):
        """
        Copy a widnows file
        """
        cmd = "COPY /y C:\\rss.reg C:\\rss.reg.bak"
        status, _ = self.session.cmd_status_output(cmd)
        logging.debug("Copy a windows file status is : %s" % status)
        return status


    def delete_windows_file(self):
        """
        Delete a widnows file
        """
        cmd = "DEL C:\rss.reg.bak"
        status, _ = self.session.cmd_status_output(cmd)
        logging.debug("Delete a windows file status is : %s" % status)
        return status


def v2v_cmd(params):
    """
    Append cmd to 'virt-v2v' and execute, optionally return full results.

    :param params: A dictionary includes all of required parameters such as
                    'target', 'hypervisor' and 'hostname', etc.
    :return: stdout of command
    """
    if V2V_EXEC is None:
        raise ValueError('Missing command: virt-v2v')

    target = params.get('target')
    hypervisor = params.get('hypervisor')
    hostname = params.get('hostname')
    vpx_dc = params.get('vpx_dc')
    esx_ip = params.get('esx_ip')
    opts_extra = params.get('v2v_opts')

    uri_obj = Uri(hypervisor)
    # Return actual 'uri' according to 'hostname' and 'hypervisor'
    uri = uri_obj.get_uri(hostname, vpx_dc, esx_ip)

    tgt_obj = Target(target, uri)
    # Return virt-v2v command line options based on 'target' and 'hypervisor'
    options = tgt_obj.get_cmd_options(params)

    if opts_extra:
        options = options + ' ' + opts_extra

    # Construct a final virt-v2v command
    cmd = '%s %s' % (V2V_EXEC, options)
    logging.debug('%s' % cmd)
    cmd_result = utils.run(cmd, verbose=DEBUG)
    return cmd_result
