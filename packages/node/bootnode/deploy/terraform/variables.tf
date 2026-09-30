# Inputs for the shade-tree bootnode/gateway droplet module.
# Defaults mirror packages/node/bootnode/deploy/bootstrap.sh so `tofu apply` reproduces the
# hand-run one-command bring-up. This module only STANDS UP the box and hands
# off to bootstrap.sh; it never re-implements the provisioning logic.

variable "do_token" {
  description = "DigitalOcean API token (operator supplies; keep it out of VCS). Set via TF_VAR_do_token or a gitignored *.tfvars."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key material (the contents of e.g. ~/.ssh/id_ed25519.pub) that gets added to the droplet's root authorized_keys."
  type        = string
}

variable "members_json" {
  description = "Operator-owned v2 invited-member document. Commitments are public, but never use the repository demo set. Cloud-init writes this to a root-only file for bootstrap.sh."
  type        = string

  validation {
    condition = (
      can(jsondecode(var.members_json)) &&
      try(jsondecode(var.members_json).version == 2, false) &&
      try(can(tolist(jsondecode(var.members_json).members)), false) &&
      try(length(jsondecode(var.members_json).members) > 0, false) &&
      try(length(jsondecode(var.members_json).members) <= 1048576, false) &&
      try(alltrue([
        for leaf in jsondecode(var.members_json).members :
        can(regex("^\"(0|[1-9][0-9]*)\"$", jsonencode(leaf))) &&
        can(tonumber(leaf)) &&
        tonumber(leaf) < 21888242871839275222246405745257275088548364400416034343698204186575808495617
      ]), false)
    )
    error_message = "members_json must be a v2 document with 1..1048576 canonical decimal-string BN254 field elements."
  }
}

variable "droplet_name" {
  description = "Name/hostname for the droplet (also used to name the SSH key + firewall)."
  type        = string
  default     = "shade-tree-bootnode"
}

variable "region" {
  description = "DigitalOcean region slug (e.g. nyc3, sfo3, ams3, sgp1). For T-DEPLOY-2, run multiple copies of this module in different regions/ASNs."
  type        = string
  default     = "nyc3"
}

variable "droplet_size" {
  description = "DigitalOcean droplet size slug. A 1vCPU/1GB box comfortably runs Tor + the three Node units (MemoryMax=512M each)."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "image" {
  description = "Base image. bootstrap.sh targets a FRESH Ubuntu 24.04 box."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "tags" {
  description = "DigitalOcean tags applied to the droplet."
  type        = list(string)
  default     = ["shade-tree", "bootnode", "gateway"]
}

# ---- handoff to bootstrap.sh (env tunables it reads) ----

variable "git_repo" {
  description = "Git URL the box clones (passed to bootstrap.sh as SHADE_TREE_REPO). Also used to derive the raw.githubusercontent.com slug for fetching bootstrap.sh itself."
  type        = string
  default     = "https://github.com/dmarzzz/shade-tree-node"

  validation {
    condition     = can(regex("^https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+([.]git)?$", var.git_repo))
    error_message = "git_repo must be an HTTPS GitHub repository URL such as https://github.com/owner/repo."
  }
}

variable "git_ref" {
  description = "Pinned branch/tag/sha to deploy (SHADE_TREE_REF). Pin a tag or sha for reproducibility; T-DEPLOY-6's rolling-update.sh moves a live box to a new ref later."
  type        = string
  default     = "main"

  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$", var.git_ref)) &&
      !strcontains(var.git_ref, "..") &&
      !strcontains(var.git_ref, "//") &&
      !endswith(var.git_ref, "/") &&
      !endswith(var.git_ref, ".")
    )
    error_message = "git_ref must be a shell-safe branch, tag, or SHA without traversal, spaces, or metacharacters."
  }
}

variable "admission" {
  description = "Bootnode admission policy (SHADE_TREE_ADMISSION): 'open' or 'stake'."
  type        = string
  default     = "open"

  validation {
    condition     = contains(["open", "stake"], var.admission)
    error_message = "admission must be either \"open\" or \"stake\"."
  }
}

variable "bootnode_port" {
  description = "Loopback backend port for the bootnode (SHADE_TREE_BOOTNODE_PORT). Published as an onion; NEVER opened to clearnet."
  type        = number
  default     = 8877

  validation {
    condition     = floor(var.bootnode_port) == var.bootnode_port && var.bootnode_port >= 1024 && var.bootnode_port <= 65535
    error_message = "bootnode_port must be an integer in 1024..65535."
  }
}

variable "gateway_port" {
  description = "Loopback backend port for the gateway (SHADE_TREE_GATEWAY_PORT). Published as an onion; NEVER opened to clearnet."
  type        = number
  default     = 8443

  validation {
    condition     = floor(var.gateway_port) == var.gateway_port && var.gateway_port >= 1024 && var.gateway_port <= 65535
    error_message = "gateway_port must be an integer in 1024..65535."
  }
}

variable "tor_socks_port" {
  description = "Local Tor SOCKS port used for the verify curl in the outputs. bootstrap.sh currently pins the heartbeat's SHADE_TREE_TOR_PORT to 9050; this is informational for the operator's verify command."
  type        = number
  default     = 9050

  validation {
    condition     = floor(var.tor_socks_port) == var.tor_socks_port && var.tor_socks_port >= 1024 && var.tor_socks_port <= 65535
    error_message = "tor_socks_port must be an integer in 1024..65535."
  }
}

# ---- firewall ----

variable "ssh_allowed_cidrs" {
  description = "CIDRs allowed to reach SSH (port 22). Lock this to your admin IP(s) in production; default is open. The bootnode/gateway themselves take NO inbound clearnet ports (they are onion services)."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}
