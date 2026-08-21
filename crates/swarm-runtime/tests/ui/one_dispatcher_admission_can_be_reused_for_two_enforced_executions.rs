use swarm_runtime::dispatcher::RoutedActionRequest;

fn execute_once(_admission: RoutedActionRequest) {}

fn main() {
    fn malicious_router(admission: RoutedActionRequest) {
        execute_once(admission.clone());
        execute_once(admission);
    }

    let _ = malicious_router;
}
