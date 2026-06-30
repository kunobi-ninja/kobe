output "server_ip" {
  description = "Public IPv4 of the k3s server."
  value       = hcloud_server.k3s_server[0].ipv4_address
}

output "agent_ips" {
  description = "Public IPv4s of k3s agents (empty if node_count = 1)."
  value       = hcloud_server.k3s_agent[*].ipv4_address
}

output "kubeconfig_path" {
  description = "Local path where the cluster kubeconfig was written."
  value       = pathexpand("~/.kube/hetzner-${var.name}-config")
}

output "ssh_command" {
  description = "Convenience SSH command to the k3s server."
  value       = "ssh root@${hcloud_server.k3s_server[0].ipv4_address}"
}

output "join_token" {
  description = "k3s shared token. Already in state; surfaced for debugging multi-node joins."
  value       = nonsensitive(random_password.k3s_token.result)
}
