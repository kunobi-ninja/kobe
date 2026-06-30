variable "name" {
  description = "Prefix for all Hetzner Cloud resources and the local kubeconfig filename."
  type        = string
  default     = "kobe-demo"
}

variable "location" {
  description = "Hetzner Cloud datacenter (nbg1=Nuremberg, fsn1=Falkenstein, hel1=Helsinki, ash=Ashburn, hil=Hillsboro)."
  type        = string
  default     = "nbg1"
}

variable "server_type" {
  description = "Hetzner Cloud server type. cx22 = 2 vCPU / 4 GB / ~4 EUR/mo, enough for the demo."
  type        = string
  default     = "cx22"
}

variable "node_count" {
  description = "Total k3s nodes. 1 = single-node (server only). >1 = 1 server + (node_count - 1) agents."
  type        = number
  default     = 1
  validation {
    condition     = var.node_count >= 1
    error_message = "node_count must be at least 1."
  }
}

variable "ssh_public_key_path" {
  description = "Path to the Ed25519 SSH public key authorized on the VM. Same key the kobe AccessPolicy expects."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "k3s_version" {
  description = "k3s release channel/tag (INSTALL_K3S_VERSION). Matches the demo pool's inner k3s."
  type        = string
  default     = "v1.31.3+k3s1"
}

variable "allowed_api_cidr" {
  description = "CIDR allowed on ports 22 + 6443. Empty = auto-detect caller's public IP via icanhazip.com. Set to \"0.0.0.0/0\" for public access (NOT recommended)."
  type        = string
  default     = ""
}
