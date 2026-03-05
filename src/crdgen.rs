use kube::CustomResourceExt;

mod crd;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let name = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match name {
        "clusterpoolprofiles" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::ClusterPoolProfile::crd()).unwrap()
        ),
        "clusterclaims" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::ClusterClaim::crd()).unwrap()
        ),
        "authpolicies" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::AuthPolicy::crd()).unwrap()
        ),
        "datastores" => print!(
            "{}",
            serde_yaml_ng::to_string(&crd::DataStore::crd()).unwrap()
        ),
        _ => {
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::ClusterPoolProfile::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::ClusterClaim::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::AuthPolicy::crd()).unwrap()
            );
            println!("---");
            print!(
                "{}",
                serde_yaml_ng::to_string(&crd::DataStore::crd()).unwrap()
            );
        }
    }
}
