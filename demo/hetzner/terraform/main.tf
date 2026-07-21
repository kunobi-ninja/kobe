terraform {
  required_version = ">= 1.5.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.48"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "hcloud" {
  # HCLOUD_TOKEN env var is read automatically.
}

# Auto-detect caller's public IP unless allowed_api_cidr is set explicitly.
data "http" "my_ip" {
  count = var.allowed_api_cidr == "" ? 1 : 0
  url   = "https://icanhazip.com"
}

locals {
  api_cidr = var.allowed_api_cidr != "" ? var.allowed_api_cidr : "${trimspace(data.http.my_ip[0].response_body)}/32"
}

resource "hcloud_ssh_key" "demo" {
  name       = "${var.name}-key"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

# Shared k3s token: server installs as the cluster secret; agents present it to join.
resource "random_password" "k3s_token" {
  length  = 32
  special = false
}

# Private network so agents can reach the server on a stable internal IP.
resource "hcloud_network" "demo" {
  name     = "${var.name}-net"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "demo" {
  network_id   = hcloud_network.demo.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

resource "hcloud_firewall" "demo" {
  name = "${var.name}-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.api_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "6443"
    source_ips = [local.api_cidr]
  }

  # ICMP for diagnostics
  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = [local.api_cidr]
  }
}

# --- k3s server (count = 1) --------------------------------------------------
resource "hcloud_server" "k3s_server" {
  count = 1

  name        = "${var.name}-server"
  server_type = var.server_type
  image       = "ubuntu-24.04"
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.demo.id]
  firewall_ids = [hcloud_firewall.demo.id]

  network {
    network_id = hcloud_network.demo.id
    ip         = "10.0.1.10"
  }

  user_data = templatefile("${path.module}/cloud-init.server.yaml.tftpl", {
    k3s_version = var.k3s_version
    k3s_token   = random_password.k3s_token.result
  })

  depends_on = [hcloud_network_subnet.demo]
}

# --- k3s agents (count = node_count - 1) -------------------------------------
resource "hcloud_server" "k3s_agent" {
  count = var.node_count - 1

  name        = "${var.name}-agent-${count.index + 1}"
  server_type = var.server_type
  image       = "ubuntu-24.04"
  location    = var.location

  ssh_keys     = [hcloud_ssh_key.demo.id]
  firewall_ids = [hcloud_firewall.demo.id]

  network {
    network_id = hcloud_network.demo.id
    ip         = "10.0.1.${20 + count.index}"
  }

  user_data = templatefile("${path.module}/cloud-init.agent.yaml.tftpl", {
    k3s_version       = var.k3s_version
    k3s_token         = random_password.k3s_token.result
    server_private_ip = hcloud_server.k3s_server[0].network[*].ip[0]
  })

  depends_on = [hcloud_server.k3s_server]
}

# --- Fetch kubeconfig from server to local ~/.kube/hetzner-<name>-config -----
# Polls SSH up to ~3 min, scp's the k3s kubeconfig, and rewrites:
#   - 127.0.0.1 → <public-ip>
#   - cluster.insecure-skip-tls-verify: true (server cert doesn't include the
#     public IP; firewall already restricts 6443 to caller IP).
resource "null_resource" "fetch_kubeconfig" {
  triggers = {
    server_id  = hcloud_server.k3s_server[0].id
    public_ip  = hcloud_server.k3s_server[0].ipv4_address
    config_out = pathexpand("~/.kube/hetzner-${var.name}-config")
    ctx_name   = "${var.name}-hetzner"
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      IP="${self.triggers.public_ip}"
      OUT="${self.triggers.config_out}"
      echo "Waiting for SSH on $IP (up to 180s)..."
      for i in $(seq 1 60); do
        if ssh -o BatchMode=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
               -o ConnectTimeout=3 root@"$IP" 'exit 0' 2>/dev/null; then
          echo "SSH ready (attempt $i)."
          break
        fi
        sleep 3
      done

      echo "Waiting for /etc/rancher/k3s/k3s.yaml on $IP (up to 180s)..."
      for i in $(seq 1 60); do
        if ssh -o BatchMode=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
               root@"$IP" 'test -f /etc/rancher/k3s/k3s.yaml' 2>/dev/null; then
          echo "k3s kubeconfig present (attempt $i)."
          break
        fi
        sleep 3
      done

      mkdir -p "$(dirname "$OUT")"
      export CTX="${self.triggers.ctx_name}"
      ssh -o BatchMode=yes -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
          root@"$IP" 'cat /etc/rancher/k3s/k3s.yaml' \
        | sed "s|127.0.0.1|$IP|" \
        | yq 'del(.clusters[].cluster."certificate-authority-data")
              | .clusters[].cluster."insecure-skip-tls-verify" = true
              | (.clusters[].name, .contexts[].name, .contexts[].context.cluster,
                 .contexts[].context.user, .users[].name, ."current-context") = strenv(CTX)' \
        > "$OUT"
      chmod 0600 "$OUT"
      echo "Wrote $OUT"
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -f ${self.triggers.config_out}"
  }

  depends_on = [hcloud_server.k3s_server]
}
