use kube::CustomResourceExt;

mod crd;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match name {
        "clusterpools" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::ClusterPool::crd()).unwrap()
        ),
        "clusterleases" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::ClusterLease::crd()).unwrap()
        ),
        "clusterinstances" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::ClusterInstance::crd()).unwrap()
        ),
        "verifiedteardownevidence" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::VerifiedTeardownEvidence::crd()).unwrap()
        ),
        "accesspolicies" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::AccessPolicy::crd()).unwrap()
        ),
        "bootstrapconfigs" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::BootstrapConfig::crd()).unwrap()
        ),
        "kobestores" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::KobeStore::crd()).unwrap()
        ),
        "cidrclaims" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::CIDRClaim::crd()).unwrap()
        ),
        "cidrpools" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::CIDRPool::crd()).unwrap()
        ),
        "sandboxpools" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::SandboxPool::crd()).unwrap()
        ),
        "sandboxleases" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::SandboxLease::crd()).unwrap()
        ),
        "sandboxexecutions" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::SandboxExecution::crd()).unwrap()
        ),
        _ => {
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::ClusterPool::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::ClusterLease::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::ClusterInstance::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::VerifiedTeardownEvidence::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::AccessPolicy::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::BootstrapConfig::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::KobeStore::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::CIDRClaim::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::CIDRPool::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::SandboxPool::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::SandboxLease::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::SandboxExecution::crd()).unwrap()
            );
        }
    }
}
