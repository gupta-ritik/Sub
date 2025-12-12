"""
Flask IP Subnetting + VLSM app
Features:
- Bootstrap UI
- Animated network diagram in result page
- Auto-detect IP class
- Export calculation to PDF (ReportLab)
- VLSM: multiple subnet generation based on required host counts

Note: templates are in the templates/ folder.
"""
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import ipaddress
import math
import io
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import json

app = Flask(__name__)
app.secret_key = "change_this_to_a_secret_in_production"  # required for session storage


def ip_class(ip_str):
    """Return IPv4 class based on first octet."""
    try:
        first_octet = int(ip_str.split('.')[0])
    except Exception:
        return "Unknown"
    if 1 <= first_octet <= 126:
        return "Class A"
    if 128 <= first_octet <= 191:
        return "Class B"
    if 192 <= first_octet <= 223:
        return "Class C"
    return "Special / Reserved"


def wildcard_from_mask(mask_str):
    return ".".join([str(255 - int(x)) for x in mask_str.split('.')])


def binary_repr_ip(x):
    return " ".join([bin(int(o))[2:].zfill(8) for o in x.split('.')])


def calculate_network_info(ip, mask):
    """Return dictionary with subnet calculation for a single network."""
    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    num_addrs = network.num_addresses
    usable_hosts = num_addrs - 2 if num_addrs > 2 else (1 if num_addrs == 1 else 0)
    hosts = list(network.hosts()) if num_addrs > 2 else []
    first_host = str(hosts[0]) if hosts else "N/A"
    last_host = str(hosts[-1]) if hosts else "N/A"

    data = {
        "ip": ip,
        "mask": mask,
        "cidr": network.prefixlen,
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "total_addresses": num_addrs,
        "usable_hosts": usable_hosts,
        "first_host": first_host,
        "last_host": last_host,
        "wildcard_mask": wildcard_from_mask(mask),
        "binary_ip": binary_repr_ip(ip),
        "binary_mask": binary_repr_ip(mask),
        "class": ip_class(ip)
    }
    return data


@app.route('/')
def index():
    """Main page: choose single-subnet or VLSM"""
    return render_template('index.html')


@app.route('/calculate', methods=['POST'])
def calculate():
    """
    Calculate subnet information for a single network.
    Stores results in session for PDF export.
    """
    ip = request.form.get('ip', '').strip()
    mask = request.form.get('mask', '').strip()
    try:
        data = calculate_network_info(ip, mask)
    except Exception as e:
        flash(f"Invalid IP or mask: {e}", 'danger')
        return redirect(url_for('index'))

    # store last result in session for export
    session['last_result'] = json.dumps(data)
    return render_template('result.html', data=data)


# -----------------------------
# VLSM: allocation helper
# -----------------------------
def prefix_for_hosts(required_hosts):
    """
    For given required_hosts (usable), compute the smallest prefix length that can
    accommodate them (including network/broadcast addresses).
    """
    # need addresses = required_hosts + 2 (network + broadcast)
    needed = required_hosts + 2
    power = math.ceil(math.log2(needed))
    block_size = 2 ** power
    prefix = 32 - power
    return prefix, block_size


def allocate_vlsm(base_network_str, host_requirements):
    """
    Allocate subnets within base_network (e.g., "192.168.1.0/24")
    host_requirements: list of integers (hosts required per subnet)
    Returns list of allocations or raises ValueError if cannot fit.
    Strategy:
      - sort host_requirements descending (largest first)
      - for each requirement compute needed prefix
      - allocate subnet at current_address with that prefix
      - move current_address to broadcast + 1
    """
    base_net = ipaddress.ip_network(base_network_str, strict=False)
    base_start = int(base_net.network_address)
    base_end = int(base_net.broadcast_address)

    # sort with indices so we can return original order
    requirements = sorted(enumerate(host_requirements), key=lambda x: -x[1])
    allocations = [None] * len(host_requirements)
    current = base_start

    for idx, hosts in requirements:
        prefix, block_size = prefix_for_hosts(hosts)
        # create candidate network at current address with computed prefix
        try:
            candidate = ipaddress.ip_network((current, prefix), strict=False)
        except Exception:
            # invalid network (e.g., prefix smaller than parent), try to align by ensuring prefix >= base prefix
            candidate = ipaddress.ip_network((current, prefix), strict=False)

        # ensure candidate fits within base network
        if int(candidate.broadcast_address) > base_end:
            raise ValueError(f"Not enough address space to allocate {hosts} hosts (required /{prefix}).")
        allocations[idx] = {
            "required_hosts": hosts,
            "prefix": prefix,
            "network": str(candidate.network_address),
            "broadcast": str(candidate.broadcast_address),
            "total_addresses": candidate.num_addresses,
            "usable_hosts": candidate.num_addresses - 2 if candidate.num_addresses > 2 else (1 if candidate.num_addresses == 1 else 0),
            "first_host": str(list(candidate.hosts())[0]) if candidate.num_addresses > 2 else "N/A",
            "last_host": str(list(candidate.hosts())[-1]) if candidate.num_addresses > 2 else "N/A",
            "cidr": f"/{prefix}"
        }
        # move current to next available address
        current = int(candidate.broadcast_address) + 1

    return allocations


@app.route('/vlsm')
def vlsm():
    """VLSM form page"""
    return render_template('vlsm.html')


@app.route('/vlsm_calculate', methods=['POST'])
def vlsm_calculate():
    """
    Accepts:
      - base_ip (string) and base_mask (string) OR base_network (like 10.0.0.0/24)
      - list of host requirements from the form (comma-separated or multiple inputs)
    Performs allocation and renders vlsm_result.html
    """
    base_ip = request.form.get('base_ip', '').strip()
    base_mask = request.form.get('base_mask', '').strip()
    base_network = request.form.get('base_network', '').strip()
    hosts_raw = request.form.get('hosts', '').strip()

    # parse hosts: accept comma separated e.g. "50,20,10" or whitespace separated
    try:
        host_list = [int(h) for h in hosts_raw.replace(',', ' ').split() if h]
        if not host_list:
            flash("Provide at least one host requirement.", 'danger')
            return redirect(url_for('vlsm'))
    except ValueError:
        flash("Host requirements must be integers separated by comma or space.", 'danger')
        return redirect(url_for('vlsm'))

    # build base network string
    if base_network:
        base_str = base_network
    else:
        if not base_ip or not base_mask:
            flash("Provide base network (either Base Network or Base IP + Mask).", 'danger')
            return redirect(url_for('vlsm'))
        base_str = f"{base_ip}/{base_mask}"

    try:
        # test base network validity
        ipaddress.ip_network(base_str, strict=False)
    except Exception as e:
        flash(f"Invalid base network: {e}", 'danger')
        return redirect(url_for('vlsm'))

    # attempt allocation
    try:
        allocations = allocate_vlsm(base_str, host_list)
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('vlsm'))

    # store for PDF export
    session['last_vlsm'] = json.dumps({
        "base": base_str,
        "allocations": allocations
    })
    return render_template('vlsm_result.html', base=base_str, allocations=allocations)


@app.route('/export_pdf_single')
def export_pdf_single():
    """Export last single-subnet result to PDF using reportlab."""
    last_json = session.get('last_result')
    if not last_json:
        flash("No calculation to export. Run a calculation first.", 'warning')
        return redirect(url_for('index'))

    data = json.loads(last_json)
    # create PDF in-memory
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    x = 40
    y = height - 40
    p.setFont("Helvetica-Bold", 14)
    p.drawString(x, y, "IP Subnetting Result")
    y -= 30
    p.setFont("Helvetica", 11)
    for k in ("ip", "mask", "cidr", "class", "network_address", "broadcast_address",
              "total_addresses", "usable_hosts", "first_host", "last_host", "wildcard_mask"):
        p.drawString(x, y, f"{k.replace('_',' ').title()}: {data.get(k)}")
        y -= 18
        if y < 80:
            p.showPage()
            y = height - 40

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="subnet_result.pdf", mimetype='application/pdf')


@app.route('/export_pdf_vlsm')
def export_pdf_vlsm():
    """Export last VLSM allocation to PDF."""
    last_json = session.get('last_vlsm')
    if not last_json:
        flash("No VLSM allocation to export. Run a VLSM calculation first.", 'warning')
        return redirect(url_for('vlsm'))

    obj = json.loads(last_json)
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    x = 40
    y = height - 40
    p.setFont("Helvetica-Bold", 14)
    p.drawString(x, y, f"VLSM Allocation for {obj['base']}")
    y -= 30
    p.setFont("Helvetica", 11)
    for idx, alloc in enumerate(obj['allocations'], start=1):
        p.drawString(x, y, f"Subnet {idx}: {alloc['network']}{alloc['cidr']}")
        y -= 16
        p.drawString(x + 12, y, f"Required hosts: {alloc['required_hosts']}, Usable hosts: {alloc['usable_hosts']}, Total: {alloc['total_addresses']}")
        y -= 16
        p.drawString(x + 12, y, f"Broadcast: {alloc['broadcast']}, First: {alloc['first_host']}, Last: {alloc['last_host']}")
        y -= 22
        if y < 80:
            p.showPage()
            y = height - 40

    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="vlsm_allocation.pdf", mimetype='application/pdf')


if __name__ == "__main__":
    app.run(debug=True)
