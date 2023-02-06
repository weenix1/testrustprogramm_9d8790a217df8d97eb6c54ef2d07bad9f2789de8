//1. create Root Node
cargo run -- -i -l /ip4/127.0.0.1/tcp/44400

//2. create provider Node, reference to Root
cargo run -- -p -r /ip4/127.0.0.1/tcp/44400

//3. create client Node, optionally specify listen Address, so client-react-app can find it
cargo run -- -c -r /ip4/127.0.0.1/tcp/44400 -l /ip4/127.0.0.1/tcp/44402