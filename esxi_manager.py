import io
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import paramiko

logger = logging.getLogger(__name__)


def get_ssh_client(host: str, port: int, user: str, password: str, timeout: int = 15) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=user, password=password, timeout=timeout)
    return ssh


def test_esxi_connection(host: str, port: int, user: str, password: str) -> Tuple[bool, str]:
    try:
        ssh = get_ssh_client(host, port, user, password, timeout=10)
        _, stdout, _ = ssh.exec_command("vmware -v")
        version = stdout.read().decode().strip()
        ssh.close()
        return True, version or "Connected successfully"
    except Exception as e:
        return False, str(e)


def get_datastores(host: str, port: int, user: str, password: str) -> List[str]:
    datastores = []
    try:
        ssh = get_ssh_client(host, port, user, password, timeout=10)
        _, stdout, _ = ssh.exec_command("ls -1 /vmfs/volumes")
        lines = stdout.read().decode().splitlines()
        ssh.close()
        for line in lines:
            name = line.strip()
            # Exclude UUID symlinks and system folders
            if name and not re.match(r"^[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}$", name):
                datastores.append(name)
    except Exception as e:
        logger.error(f"Failed to list datastores on {host}: {e}")
    return datastores or ["datastore1"]


def get_vm_id_by_name(ssh: paramiko.SSHClient, vm_name: str) -> Optional[int]:
    _, stdout, _ = ssh.exec_command("vim-cmd vmsvc/getallvms")
    lines = stdout.read().decode().splitlines()
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 2 and parts[1] == vm_name and parts[0].isdigit():
            return int(parts[0])
    return None


def get_vnic_device_id(ssh: paramiko.SSHClient, vmid: int) -> int:
    """Finds the device ID of the first vNIC (usually 4000)."""
    try:
        _, stdout, _ = ssh.exec_command(f"vim-cmd vmsvc/device.getdevices {vmid}")
        output = stdout.read().decode()
        # Look for VirtualEthernetCard and its key
        match = re.search(r"\(vim\.vm\.device\.VirtualEthernetCard\)\s*\{.*?key\s*=\s*(\d+)", output, re.DOTALL)
        if match:
            return int(match.group(1))
    except Exception as e:
        logger.warning(f"Failed to detect vNIC device id for VM {vmid}: {e}")
    return 4000


def set_vnic_connection(esxi_host: str, port: int, user: str, password: str, vmid: int, connected: bool) -> bool:
    """Connects or disconnects the vNIC on ESXi to suspend or restore network traffic."""
    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        dev_id = get_vnic_device_id(ssh, vmid)
        flag = 1 if connected else 0
        cmd = f"vim-cmd vmsvc/device.connection {vmid} {dev_id} {flag}"
        _, stdout, stderr = ssh.exec_command(cmd)
        err = stderr.read().decode().strip()
        ssh.close()
        if err:
            logger.error(f"Error changing vNIC state on VM {vmid}: {err}")
            return False
        logger.info(f"vNIC on VM {vmid} set to connected={connected}")
        return True
    except Exception as e:
        logger.error(f"Failed to change vNIC state for VM {vmid} on ESXi {esxi_host}: {e}")
        return False


def power_vm(esxi_host: str, port: int, user: str, password: str, vmid: int, action: str) -> Tuple[bool, str]:
    """Action can be 'on', 'off', 'reset', 'shutdown', 'reboot'."""
    cmd_map = {
        "on": f"vim-cmd vmsvc/power.on {vmid}",
        "off": f"vim-cmd vmsvc/power.off {vmid}",
        "reset": f"vim-cmd vmsvc/power.reset {vmid}",
        "shutdown": f"vim-cmd vmsvc/power.shutdown {vmid}",
        "reboot": f"vim-cmd vmsvc/power.reboot {vmid}",
    }
    cmd = cmd_map.get(action)
    if not cmd:
        return False, f"Unknown action {action}"

    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()
        if err and "already powered on" not in err.lower() and "already powered off" not in err.lower():
            return False, err
        return True, out or "Success"
    except Exception as e:
        return False, str(e)


def generate_netplan_yaml(
    primary_ipv4: str,
    gateway_ipv4: str,
    netmask_or_prefix: str = "24",
    extra_ips: Optional[List[str]] = None,
    ipv6: Optional[str] = None,
    ipv6_gateway: Optional[str] = None,
    nameservers: Optional[List[str]] = None,
    iface: str = "eth0",
) -> str:
    """Generates clean Ubuntu Netplan v2 YAML exactly matching user specification."""
    clean_ip = primary_ipv4.strip()
    prefix = str(netmask_or_prefix).strip().lstrip("/")
    if "/" not in clean_ip:
        primary_addr = f"{clean_ip}/{prefix}"
    else:
        primary_addr = clean_ip

    addresses = [primary_addr]
    if extra_ips:
        for eip in extra_ips:
            eip = eip.strip()
            if eip:
                if "/" not in eip:
                    addresses.append(f"{eip}/{prefix}")
                else:
                    addresses.append(eip)

    if ipv6 and ipv6.strip():
        addresses.append(ipv6.strip())

    ns = nameservers or ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"]
    ns_formatted = ", ".join(ns)

    yaml_lines = [
        "network:",
        "  version: 2",
        "  renderer: networkd",
        "  ethernets:",
        f"    {iface}:",
        "      dhcp4: false",
        "      dhcp6: false",
        "      addresses:",
    ]
    for addr in addresses:
        yaml_lines.append(f"        - {addr}")

    yaml_lines.append("      routes:")
    yaml_lines.append("        - to: 0.0.0.0/0")
    yaml_lines.append(f"          via: {gateway_ipv4.strip()}")

    if ipv6_gateway and ipv6_gateway.strip():
        yaml_lines.append("        - to: ::/0")
        yaml_lines.append(f"          via: {ipv6_gateway.strip()}")

    yaml_lines.append("      nameservers:")
    yaml_lines.append(f"        addresses: [{ns_formatted}]")
    yaml_lines.append("")

    return "\n".join(yaml_lines)


def apply_netplan_to_vm(
    vm_ip: str,
    ssh_user: str,
    ssh_password: str,
    netplan_content: str,
    ssh_port: int = 22,
    timeout: int = 20,
) -> Tuple[bool, str]:
    """Applies Netplan YAML directly on the target Ubuntu VM via SSH."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vm_ip, port=ssh_port, username=ssh_user, password=ssh_password, timeout=timeout)

        # Write to temporary file then move with sudo
        sftp = ssh.open_sftp()
        with sftp.file("/tmp/01-netcfg.yaml", "w") as f:
            f.write(netplan_content)
        sftp.close()

        # Apply netplan
        cmd = (
            "echo " + ssh_password + " | sudo -S mv /tmp/01-netcfg.yaml /etc/netplan/01-netcfg.yaml && "
            "sudo chmod 600 /etc/netplan/01-netcfg.yaml && "
            "sudo netplan apply"
        )
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()
        if "error" in err.lower():
            return False, err
        return True, "Netplan applied successfully"
    except Exception as e:
        return False, str(e)


def create_vm_on_esxi(
    esxi_host: str,
    esxi_port: int,
    esxi_user: str,
    esxi_password: str,
    vm_name: str,
    cpus: int,
    ram_mb: int,
    disk_gb: int,
    datastore: str,
    template_vmdk: str,
    network_name: str = "VM Network",
    mac_address: Optional[str] = None,
) -> Tuple[bool, Optional[int], str]:
    """
    Creates a new VM on ESXi by:
    1. Creating the VM directory on datastore.
    2. Cloning the Golden Image template VMDK with thin provisioning.
    3. Expanding disk if requested size is larger.
    4. Generating the .vmx file and registering the VM.
    5. Powering on the newly registered VM.
    """
    clean_vm_name = re.sub(r"[^a-zA-Z0-9_-]", "_", vm_name.strip())
    vm_dir = f"/vmfs/volumes/{datastore}/{clean_vm_name}"
    vmx_path = f"{vm_dir}/{clean_vm_name}.vmx"
    vmdk_path = f"{vm_dir}/{clean_vm_name}.vmdk"

    try:
        ssh = get_ssh_client(esxi_host, esxi_port, esxi_user, esxi_password)

        # 1. Create directory
        _, _, stderr = ssh.exec_command(f"mkdir -p '{vm_dir}'")
        err = stderr.read().decode().strip()
        if err:
            ssh.close()
            return False, None, f"Failed to create VM directory: {err}"

        # 2. Clone VMDK thin provisioned
        clone_cmd = f"vmkfstools -i '{template_vmdk}' -d thin '{vmdk_path}'"
        _, stdout, stderr = ssh.exec_command(clone_cmd)
        err = stderr.read().decode().strip()
        if err and "Cloning done with exit code 0" not in stdout.read().decode():
            if "Destination disk format" not in err and "already exists" not in err:
                ssh.close()
                return False, None, f"Failed to clone VMDK: {err}"

        # 3. Expand disk if larger
        if disk_gb and disk_gb > 0:
            expand_cmd = f"vmkfstools -X {disk_gb}G '{vmdk_path}'"
            ssh.exec_command(expand_cmd)

        # 4. Generate VMX content
        mac_config = 'ethernet0.addressType = "generated"'
        if mac_address and mac_address.strip():
            mac_config = f'ethernet0.addressType = "static"\nethernet0.address = "{mac_address.strip()}"'

        vmx_content = f"""\
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "14"
vmci0.present = "TRUE"
displayName = "{clean_vm_name}"
guestOS = "ubuntu-64"
memSize = "{ram_mb}"
numvcpus = "{cpus}"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "{clean_vm_name}.vmdk"
scsi0:0.deviceType = "scsi-hardDisk"
ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.networkName = "{network_name}"
{mac_config}
ethernet0.startConnected = "TRUE"
ethernet0.connected = "TRUE"
powerType.powerOff = "soft"
powerType.reset = "soft"
powerType.suspend = "soft"
"""
        sftp = ssh.open_sftp()
        with sftp.file(vmx_path, "w") as f:
            f.write(vmx_content)
        sftp.close()

        # 5. Register VM
        reg_cmd = f"vim-cmd solo/registervm '{vmx_path}'"
        _, stdout, stderr = ssh.exec_command(reg_cmd)
        reg_out = stdout.read().decode().strip()
        reg_err = stderr.read().decode().strip()

        vmid = None
        if reg_out.isdigit():
            vmid = int(reg_out)
        else:
            # Look up vmid by name
            vmid = get_vm_id_by_name(ssh, clean_vm_name)

        if not vmid:
            ssh.close()
            return False, None, f"Failed to register VM: {reg_err or reg_out}"

        # 6. Power on VM
        ssh.exec_command(f"vim-cmd vmsvc/power.on {vmid}")
        ssh.close()
        return True, vmid, f"VM {clean_vm_name} created and powered on with VMID {vmid}"
    except Exception as e:
        return False, None, str(e)


def rebuild_vm_on_esxi(
    esxi_host: str,
    esxi_port: int,
    esxi_user: str,
    esxi_password: str,
    vmid: int,
    vm_name: str,
    datastore: str,
    template_vmdk: str,
    disk_gb: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Rebuilds an existing VM:
    1. Powers off VM.
    2. Deletes the OS disk.
    3. Re-clones fresh golden image.
    4. Powers on VM.
    """
    clean_vm_name = re.sub(r"[^a-zA-Z0-9_-]", "_", vm_name.strip())
    vm_dir = f"/vmfs/volumes/{datastore}/{clean_vm_name}"
    vmdk_path = f"{vm_dir}/{clean_vm_name}.vmdk"

    try:
        ssh = get_ssh_client(esxi_host, esxi_port, esxi_user, esxi_password)

        # 1. Power off
        ssh.exec_command(f"vim-cmd vmsvc/power.off {vmid}")
        time.sleep(3)

        # 2. Delete existing disk
        ssh.exec_command(f"vmkfstools -U '{vmdk_path}'")
        time.sleep(1)

        # 3. Clone fresh disk
        clone_cmd = f"vmkfstools -i '{template_vmdk}' -d thin '{vmdk_path}'"
        _, stdout, stderr = ssh.exec_command(clone_cmd)
        err = stderr.read().decode().strip()
        if err and "Cloning done with exit code 0" not in stdout.read().decode():
            ssh.close()
            return False, f"Failed to re-clone VMDK: {err}"

        # 4. Expand if needed
        if disk_gb and disk_gb > 0:
            ssh.exec_command(f"vmkfstools -X {disk_gb}G '{vmdk_path}'")

        # 5. Power on
        ssh.exec_command(f"vim-cmd vmsvc/power.on {vmid}")
        ssh.close()
        return True, f"VM {clean_vm_name} successfully rebuilt from template"
    except Exception as e:
        return False, str(e)
