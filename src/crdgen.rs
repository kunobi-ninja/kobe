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
        "accesspolicies" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::AccessPolicy::crd()).unwrap()
        ),
        "kobestores" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::KobeStore::crd()).unwrap()
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
                serde_yaml_ng::to_string(&crd::AccessPolicy::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::KobeStore::crd()).unwrap()
            );
        }
    }
}
