output "droplet_id" {
  description = "DigitalOcean droplet ID."
  value       = digitalocean_droplet.bootnode.id
}

output "droplet_name" {
  description = "Droplet name/hostname."
  value       = digitalocean_droplet.bootnode.name
}

output "ipv4_address" {
  description = "Public IPv4 of the box (SSH target; NOT how clients reach the services — those are onions)."
  value       = digitalocean_droplet.bootnode.ipv4_address
}

output "region" {
  description = "Region the box was placed in (useful when running the module per-region for T-DEPLOY-2)."
  value       = digitalocean_droplet.bootnode.region
}

output "ssh_command" {
  description = "SSH to the box."
  value       = "ssh root@${digitalocean_droplet.bootnode.ipv4_address}"
}

output "provisioning_log_command" {
  description = "Tail the first-boot provisioning + bootstrap.sh output."
  value       = "ssh root@${digitalocean_droplet.bootnode.ipv4_address} 'tail -f /var/log/shade-tree-bootstrap.log'"
}

output "verify_command" {
  description = "After ~30s of descriptor propagation, print the minted bootnode onion and health-check it over Tor. The onion + pinned signer + gateway onion are also in the provisioning log."
  value = join(" && ", [
    "ssh root@${digitalocean_droplet.bootnode.ipv4_address} 'cat /opt/shade-tree/deploy-state/bootnode-hs/hostname'",
    "echo 'then, over Tor SOCKS ${var.tor_socks_port}:'",
    "ssh root@${digitalocean_droplet.bootnode.ipv4_address} 'BN=$(cat /opt/shade-tree/deploy-state/bootnode-hs/hostname); curl --socks5-hostname 127.0.0.1:${var.tor_socks_port} http://$BN/health'"
  ])
}

output "rolling_update_hint" {
  description = "Move this box to a new git ref later without re-provisioning (T-DEPLOY-6)."
  value       = "ssh root@${digitalocean_droplet.bootnode.ipv4_address} 'sudo bash /opt/shade-tree/packages/node/bootnode/deploy/rolling-update.sh <ref>'"
}
