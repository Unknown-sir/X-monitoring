import logging
import math
import re
import shlex
import struct
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
            if name and not re.match(r"^[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{12}$", name):
                datastores.append(name)
    except Exception as e:
        logger.error(f"Failed to list datastores on {host}: {e}")
    return datastores or ["datastore1"]


def get_vm_id_by_name(ssh: paramiko.SSHClient, vm_name: str) -> Optional[int]:
    _, stdout, _ = ssh.exec_command("vim-cmd vmsvc/getallvms")
    lines = stdout.read().decode().splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == vm_name and parts[0].isdigit():
            return int(parts[0])
    return None


def get_vnic_device_id(ssh: paramiko.SSHClient, vmid: int) -> int:
    """Finds the device ID of the first vNIC (usually 4000)."""
    try:
        _, stdout, _ = ssh.exec_command(f"vim-cmd vmsvc/device.getdevices {vmid}")
        output = stdout.read().decode()
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


# ==============================================================================
# Pure-Python Cloud-Init NoCloud (seed.iso) Generator
# ==============================================================================
def _both16(val: int) -> bytes:
    return struct.pack("<H", val) + struct.pack(">H", val)


def _both32(val: int) -> bytes:
    return struct.pack("<I", val) + struct.pack(">I", val)


def _dir_record(extent_lba: int, data_len: int, flags: int, name_bytes: bytes) -> bytes:
    rec_len = 33 + len(name_bytes)
    if rec_len % 2 == 1:
        pad = b"\x00"
        rec_len += 1
    else:
        pad = b""
    date_bytes = bytes([126, 1, 1, 0, 0, 0, 0])
    rec = bytearray()
    rec.append(rec_len)
    rec.append(0)
    rec += _both32(extent_lba)
    rec += _both32(data_len)
    rec += date_bytes
    rec.append(flags)
    rec.append(0)
    rec.append(0)
    rec += _both16(1)
    rec.append(len(name_bytes))
    rec += name_bytes
    rec += pad
    return bytes(rec)


def build_cloud_init_iso(meta_data: str, user_data: str, network_config: str) -> bytes:
    """
    Pure-Python ISO9660 + Joliet generator with volume label 'CIDATA'
    for cloud-init NoCloud datasource. Zero external dependencies.
    """
    files = [
        ("meta-data", "METADATA.;1", meta_data.encode("utf-8")),
        ("network-config", "NETCFG.;1", network_config.encode("utf-8")),
        ("user-data", "USERDATA.;1", user_data.encode("utf-8")),
    ]
    sector_size = 2048
    curr_lba = 25
    file_extents = []
    for joliet_name, iso_name, content in files:
        sectors_needed = max(1, math.ceil(len(content) / sector_size))
        file_extents.append((joliet_name, iso_name, content, curr_lba, sectors_needed))
        curr_lba += sectors_needed
    total_sectors = curr_lba

    def make_root_dir(use_joliet: bool) -> bytes:
        dir_lba = 24 if use_joliet else 23
        entries = bytearray()
        for name_b in (b"\x00", b"\x01"):
            entries += _dir_record(dir_lba, sector_size, 2, name_b)
        for joliet_name, iso_name, content, lba, _ in file_extents:
            nb = joliet_name.encode("utf-16be") if use_joliet else iso_name.encode("ascii")
            entries += _dir_record(lba, len(content), 0, nb)
        return bytes(entries).ljust(sector_size, b"\x00")

    pvd_root = make_root_dir(False)
    svd_root = make_root_dir(True)

    def make_path_table(big_endian: bool, root_lba: int) -> bytes:
        endian = ">" if big_endian else "<"
        pt = struct.pack(f"{endian}BBIHB", 1, 0, root_lba, 1, 0) + b"\x00"
        return pt.ljust(sector_size, b"\x00")

    pvd_pt_l = make_path_table(False, 23)
    pvd_pt_m = make_path_table(True, 23)
    svd_pt_l = make_path_table(False, 24)
    svd_pt_m = make_path_table(True, 24)

    def make_vd(is_joliet: bool) -> bytes:
        vd = bytearray(sector_size)
        vd[0] = 2 if is_joliet else 1
        vd[1:6] = b"CD001"
        vd[6] = 1
        if is_joliet:
            vd[8:40] = (" " * 16).encode("utf-16be")
            vol_id = "CIDATA".encode("utf-16be")
            vd[40:72] = vol_id + (b"\x00\x20" * (16 - len("CIDATA")))
            vd[88:91] = b"%/E"
        else:
            vd[8:40] = b" " * 32
            vd[40:72] = b"CIDATA".ljust(32, b" ")
        vd[80:88] = _both32(total_sectors)
        vd[120:124] = _both16(1)
        vd[124:128] = _both16(1)
        vd[128:132] = _both16(sector_size)
        vd[132:140] = _both32(10)
        vd[140:144] = struct.pack("<I", 21 if is_joliet else 19)
        vd[148:152] = struct.pack(">I", 22 if is_joliet else 20)
        root_rec = _dir_record(24 if is_joliet else 23, sector_size, 2, b"\x00")
        vd[156 : 156 + len(root_rec)] = root_rec
        vd[881] = 1
        return bytes(vd)

    pvd = make_vd(False)
    svd = make_vd(True)
    vdst = bytearray(sector_size)
    vdst[0] = 255
    vdst[1:6] = b"CD001"
    vdst[6] = 1

    iso = bytearray(16 * sector_size)
    iso += pvd + svd + bytes(vdst)
    iso += pvd_pt_l + pvd_pt_m + svd_pt_l + svd_pt_m
    iso += pvd_root + svd_root
    for _, _, content, _, sectors_needed in file_extents:
        iso += content.ljust(sectors_needed * sector_size, b"\x00")
    return bytes(iso)


def generate_cloud_init_configs(
    vm_name: str,
    ssh_user: str,
    ssh_password: str,
    netplan_yaml: str,
) -> Tuple[str, str, str]:
    """Builds meta-data, user-data, and network-config for cloud-init."""
    instance_id = f"{vm_name}-{int(time.time())}"
    meta_data = f"instance-id: {instance_id}\nlocal-hostname: {vm_name}\n"

    # Configure user password, root SSH login & password auth
    if ssh_user == "root":
        user_block = ""
        chpasswd_list = f"    - root:{ssh_password}"
    else:
        user_block = (
            "users:\n"
            f"  - name: {ssh_user}\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
            "    shell: /bin/bash\n"
            "    lock_passwd: false\n"
        )
        chpasswd_list = f"    - {ssh_user}:{ssh_password}\n    - root:{ssh_password}"

    user_data = (
        "#cloud-config\n"
        "disable_root: false\n"
        "ssh_pwauth: true\n"
        f"{user_block}"
        "chpasswd:\n"
        "  expire: false\n"
        "  list: |\n"
        f"{chpasswd_list}\n"
        "runcmd:\n"
        "  - sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config\n"
        "  - sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\n"
        "  - systemctl restart ssh || systemctl restart sshd\n"
        "  - netplan apply\n"
    )
    return meta_data, user_data, netplan_yaml


# ==============================================================================
# Netplan Generator & Remote Applier
# ==============================================================================
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
    """Generates clean Ubuntu Netplan v2 YAML."""
    clean_ip = primary_ipv4.strip()
    prefix = str(netmask_or_prefix).strip().lstrip("/")
    primary_addr = clean_ip if "/" in clean_ip else f"{clean_ip}/{prefix}"

    addresses = [primary_addr]
    if extra_ips:
        for eip in extra_ips:
            eip = eip.strip()
            if eip:
                addresses.append(eip if "/" in eip else f"{eip}/{prefix}")

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

        sftp = ssh.open_sftp()
        with sftp.file("/tmp/01-netcfg.yaml", "w") as f:
            f.write(netplan_content)
        sftp.close()

        quoted_pw = shlex.quote(ssh_password)
        cmd = (
            f"echo {quoted_pw} | sudo -S mv /tmp/01-netcfg.yaml /etc/netplan/01-netcfg.yaml && "
            "sudo chmod 600 /etc/netplan/01-netcfg.yaml && "
            "sudo netplan apply"
        )
        _, stdout, stderr = ssh.exec_command(cmd)
        stdout.read()
        err = stderr.read().decode().strip()
        ssh.close()
        if "error" in err.lower():
            return False, err
        return True, "Netplan applied successfully"
    except Exception as e:
        return False, str(e)


# ==============================================================================
# ESXi VM Creation & Rebuild (with Cloud-Init seed.iso)
# ==============================================================================
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
    seed_iso_bytes: Optional[bytes] = None,
) -> Tuple[bool, Optional[int], str]:
    """
    Creates a new VM on ESXi with optional cloud-init seed.iso attached on ide1:0.
    """
    clean_vm_name = re.sub(r"[^a-zA-Z0-9_-]", "_", vm_name.strip())
    vm_dir = f"/vmfs/volumes/{datastore}/{clean_vm_name}"
    vmx_path = f"{vm_dir}/{clean_vm_name}.vmx"
    vmdk_path = f"{vm_dir}/{clean_vm_name}.vmdk"
    iso_path = f"{vm_dir}/seed.iso"

    try:
        ssh = get_ssh_client(esxi_host, esxi_port, esxi_user, esxi_password)

        _, _, stderr = ssh.exec_command(f"mkdir -p '{vm_dir}'")
        err = stderr.read().decode().strip()
        if err:
            ssh.close()
            return False, None, f"Failed to create VM directory: {err}"

        clone_cmd = f"vmkfstools -i '{template_vmdk}' -d thin '{vmdk_path}'"
        _, stdout, stderr = ssh.exec_command(clone_cmd)
        clone_out = stdout.read().decode()
        err = stderr.read().decode().strip()
        if err and "Cloning done with exit code 0" not in clone_out:
            if "Destination disk format" not in err and "already exists" not in err:
                ssh.close()
                return False, None, f"Failed to clone VMDK: {err}"

        if disk_gb and disk_gb > 0:
            ssh.exec_command(f"vmkfstools -X {disk_gb}G '{vmdk_path}'")

        sftp = ssh.open_sftp()
        cdrom_block = ""
        if seed_iso_bytes:
            with sftp.file(iso_path, "wb") as f:
                f.write(seed_iso_bytes)
            cdrom_block = (
                'ide1:0.present = "TRUE"\n'
                'ide1:0.deviceType = "cdrom-image"\n'
                'ide1:0.fileName = "seed.iso"\n'
                'ide1:0.startConnected = "TRUE"\n'
            )

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
{cdrom_block}ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.networkName = "{network_name}"
{mac_config}
ethernet0.startConnected = "TRUE"
ethernet0.connected = "TRUE"
powerType.powerOff = "soft"
powerType.reset = "soft"
powerType.suspend = "soft"
"""
        with sftp.file(vmx_path, "w") as f:
            f.write(vmx_content)
        sftp.close()

        reg_cmd = f"vim-cmd solo/registervm '{vmx_path}'"
        _, stdout, stderr = ssh.exec_command(reg_cmd)
        reg_out = stdout.read().decode().strip()
        reg_err = stderr.read().decode().strip()

        vmid = int(reg_out) if reg_out.isdigit() else get_vm_id_by_name(ssh, clean_vm_name)
        if not vmid:
            ssh.close()
            return False, None, f"Failed to register VM: {reg_err or reg_out}"

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
    seed_iso_bytes: Optional[bytes] = None,
) -> Tuple[bool, str]:
    """Rebuilds an existing VM and refreshes cloud-init seed.iso if provided."""
    clean_vm_name = re.sub(r"[^a-zA-Z0-9_-]", "_", vm_name.strip())
    vm_dir = f"/vmfs/volumes/{datastore}/{clean_vm_name}"
    vmdk_path = f"{vm_dir}/{clean_vm_name}.vmdk"
    iso_path = f"{vm_dir}/seed.iso"

    try:
        ssh = get_ssh_client(esxi_host, esxi_port, esxi_user, esxi_password)

        ssh.exec_command(f"vim-cmd vmsvc/power.off {vmid}")
        time.sleep(3)

        ssh.exec_command(f"vmkfstools -U '{vmdk_path}'")
        time.sleep(1)

        clone_cmd = f"vmkfstools -i '{template_vmdk}' -d thin '{vmdk_path}'"
        _, stdout, stderr = ssh.exec_command(clone_cmd)
        clone_out = stdout.read().decode()
        err = stderr.read().decode().strip()
        if err and "Cloning done with exit code 0" not in clone_out:
            ssh.close()
            return False, f"Failed to re-clone VMDK: {err}"

        if disk_gb and disk_gb > 0:
            ssh.exec_command(f"vmkfstools -X {disk_gb}G '{vmdk_path}'")

        if seed_iso_bytes:
            sftp = ssh.open_sftp()
            with sftp.file(iso_path, "wb") as f:
                f.write(seed_iso_bytes)
            sftp.close()

        ssh.exec_command(f"vim-cmd vmsvc/power.on {vmid}")
        ssh.close()
        return True, f"VM {clean_vm_name} successfully rebuilt from template"
    except Exception as e:
        return False, str(e)


# ==============================================================================
# ESXi Snapshot Management
# ==============================================================================
def list_snapshots(esxi_host: str, port: int, user: str, password: str, vmid: int) -> Tuple[bool, List[Dict[str, Any]], str]:
    """Parses `vim-cmd vmsvc/snapshot.get <vmid>` into a flat list of snapshots."""
    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        _, stdout, stderr = ssh.exec_command(f"vim-cmd vmsvc/snapshot.get {vmid}")
        output = stdout.read().decode()
        err = stderr.read().decode().strip()
        ssh.close()
        if err and "Get Snapshot" not in output:
            return False, [], err

        snapshots: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        for raw_line in output.splitlines():
            line = raw_line.strip().lstrip("|-")
            if line.startswith("Snapshot Name"):
                if current and "id" in current:
                    snapshots.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Snapshot Id") and current is not None:
                val = line.split(":", 1)[1].strip()
                current["id"] = int(val) if val.isdigit() else val
            elif line.startswith("Snapshot Desciption") or line.startswith("Snapshot Description"):
                current["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("Snapshot Created On"):
                current["created_on"] = line.split(":", 1)[1].strip()
            elif line.startswith("Snapshot State"):
                current["state"] = line.split(":", 1)[1].strip()
        if current and "id" in current:
            snapshots.append(current)

        return True, snapshots, "OK"
    except Exception as e:
        return False, [], str(e)


def create_snapshot(
    esxi_host: str, port: int, user: str, password: str, vmid: int, name: str, description: str = ""
) -> Tuple[bool, str]:
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", name.strip()) or f"snap_{int(time.time())}"
    safe_desc = description.replace('"', "'").strip()
    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        cmd = f'vim-cmd vmsvc/snapshot.create {vmid} "{safe_name}" "{safe_desc}" 0 0'
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()
        if err:
            return False, err
        return True, out or "Snapshot created"
    except Exception as e:
        return False, str(e)


def revert_snapshot(esxi_host: str, port: int, user: str, password: str, vmid: int, snapshot_id: int) -> Tuple[bool, str]:
    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        cmd = f"vim-cmd vmsvc/snapshot.revert {vmid} {int(snapshot_id)} 0"
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()
        if err:
            return False, err
        return True, out or "Reverted to snapshot"
    except Exception as e:
        return False, str(e)


def remove_snapshot(esxi_host: str, port: int, user: str, password: str, vmid: int, snapshot_id: int) -> Tuple[bool, str]:
    try:
        ssh = get_ssh_client(esxi_host, port, user, password)
        cmd = f"vim-cmd vmsvc/snapshot.remove {vmid} {int(snapshot_id)}"
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        ssh.close()
        if err:
            return False, err
        return True, out or "Snapshot removed"
    except Exception as e:
        return False, str(e)


# ==============================================================================
# Automated ESXi VM Hardware Upgrade (CPU, RAM, SSD Disk)
# ==============================================================================
def upgrade_vm_resources_on_esxi(
    esxi_host: str,
    esxi_port: int,
    esxi_user: str,
    esxi_password: str,
    vmid: int,
    vm_name: str,
    datastore: str,
    new_cpus: int,
    new_ram_mb: int,
    new_disk_gb: int,
    expand_disk: bool = False,
) -> Tuple[bool, str]:
    clean_vm_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (vm_name or f"vm_{vmid}").strip())
    vm_dir = f"/vmfs/volumes/{datastore}/{clean_vm_name}"
    vmx_path = f"{vm_dir}/{clean_vm_name}.vmx"
    vmdk_path = f"{vm_dir}/{clean_vm_name}.vmdk"

    try:
        ssh = get_ssh_client(esxi_host, esxi_port, esxi_user, esxi_password)
        ssh.exec_command(f"vim-cmd vmsvc/power.off {int(vmid)}")
        time.sleep(3)

        sftp = ssh.open_sftp()
        try:
            with sftp.file(vmx_path, "r") as f:
                vmx_raw = f.read().decode("utf-8", errors="ignore")
        except Exception:
            sftp.close()
            ssh.close()
            return False, f"فایل VMX در مسیر {vmx_path} یافت نشد."

        lines = []
        found_cpu = False
        found_ram = False
        for line in vmx_raw.splitlines():
            if line.strip().startswith("numvcpus"):
                lines.append(f'numvcpus = "{int(new_cpus)}"')
                found_cpu = True
            elif line.strip().startswith("memSize"):
                lines.append(f'memSize = "{int(new_ram_mb)}"')
                found_ram = True
            else:
                lines.append(line)
        if not found_cpu:
            lines.append(f'numvcpus = "{int(new_cpus)}"')
        if not found_ram:
            lines.append(f'memSize = "{int(new_ram_mb)}"')

        with sftp.file(vmx_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        sftp.close()

        if expand_disk and new_disk_gb > 0:
            ssh.exec_command(f"vmkfstools -X {int(new_disk_gb)}G '{vmdk_path}'")

        ssh.exec_command(f"vim-cmd vmsvc/reload {int(vmid)}")
        time.sleep(1)
        ssh.exec_command(f"vim-cmd vmsvc/power.on {int(vmid)}")
        ssh.close()
        return True, f"منابع ماشین مجازی #{vmid} به {new_cpus} Core / {int(new_ram_mb/1024)}GB RAM / {new_disk_gb}GB SSD ارتقا یافت."
    except Exception as e:
        return False, str(e)


def expand_linux_partition_via_ssh(
    vm_ip: str,
    ssh_user: str,
    ssh_password: str,
    ssh_port: int = 22,
    retries: int = 6,
    delay_sec: int = 5,
) -> Tuple[bool, str]:
    """
    Waits briefly for VM SSH after ESXi disk expansion and runs growpart + resize2fs/xfs_growfs
    so the Linux OS immediately sees the added SSD space without manual commands.
    """
    if not vm_ip or "در انتظار" in str(vm_ip):
        return False, "آی‌پی معتبر برای اتصال SSH جهت گسترش پارتیشن وجود ندارد."

    remote_script = (
        "for d in /sys/class/scsi_disk/*/device/rescan; do echo 1 > \"$d\" 2>/dev/null || true; done; "
        "ROOT_SRC=$(findmnt -n -o SOURCE /); "
        "if [[ \"$ROOT_SRC\" =~ ^(/dev/[a-zA-Z0-9]+)p?([0-9]+)$ ]]; then "
        "DISK=\"${BASH_REMATCH[1]}\"; PART=\"${BASH_REMATCH[2]}\"; "
        "if [[ \"$ROOT_SRC\" == /dev/nvme* ]]; then DISK=\"${ROOT_SRC%p*}\"; fi; "
        "command -v growpart >/dev/null 2>&1 && growpart \"$DISK\" \"$PART\" || true; "
        "fi; "
        "FSTYPE=$(findmnt -n -o FSTYPE /); "
        "if [ \"$FSTYPE\" = \"xfs\" ]; then xfs_growfs / || true; else resize2fs \"$ROOT_SRC\" || true; fi"
    )

    last_err = ""
    for _ in range(retries):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(vm_ip, port=ssh_port, username=ssh_user or "root", password=ssh_password or "", timeout=10)
            quoted_pw = shlex.quote(ssh_password or "")
            quoted_script = shlex.quote(remote_script)
            cmd = f"echo {quoted_pw} | sudo -S bash -c {quoted_script}"
            _, stdout, stderr = ssh.exec_command(cmd, timeout=25)
            stdout.read()
            err = stderr.read().decode(errors="ignore").strip()
            ssh.close()
            return True, "پارتیشن سیستم‌عامل به صورت خودکار گسترش یافت." if not err else f"پارتیشن گسترش یافت ({err[:80]})"
        except Exception as e:
            last_err = str(e)
            time.sleep(delay_sec)
    return False, f"اتصال SSH پس از ارتقا برقرار نشد: {last_err}"
