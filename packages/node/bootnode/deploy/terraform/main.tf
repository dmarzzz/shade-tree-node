provider "digitalocean" {
  token = var.do_token
}

locals {
  # Derive owner/repo for raw.githubusercontent.com from the clone URL so there is
  # a single source of truth for which repo/ref the box provisions from.
  repo_slug = trimsuffix(replace(var.git_repo, "https://github.com/", ""), ".git")
}

# SSH key registered with DigitalOcean and injected into the droplet at create.
resource "digitalocean_ssh_key" "operator" {
  name       = "${var.droplet_name}-key"
  public_key = var.ssh_public_key
}

# The box. cloud-init user_data is a THIN wrapper: it exports the same tunables
# bootstrap.sh reads, fetches bootstrap.sh at the pinned ref, and delegates.
# All real provisioning (Node + Tor + onion mint + systemd units) lives in
# packages/node/bootnode/deploy/bootstrap.sh — this module does not duplicate it.
resource "digitalocean_droplet" "bootnode" {
  name     = var.droplet_name
  region   = var.region
  size     = var.droplet_size
  image    = var.image
  ssh_keys = [digitalocean_ssh_key.operator.fingerprint]
  tags     = var.tags

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    git_repo         = var.git_repo
    repo_slug        = local.repo_slug
    git_ref          = var.git_ref
    admission        = var.admission
    bootnode_port    = var.bootnode_port
    gateway_port     = var.gateway_port
    members_json_b64 = base64encode(var.members_json)
  })
}

# Firewall: SSH-in only, everything out. The bootnode (8877) and gateway (8443)
# are loopback-only backends published as Tor v3 onions, so they need NO inbound
# clearnet rules. Tor needs unrestricted outbound to build circuits.
resource "digitalocean_firewall" "bootnode" {
  name        = "${var.droplet_name}-fw"
  droplet_ids = [digitalocean_droplet.bootnode.id]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_cidrs
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
