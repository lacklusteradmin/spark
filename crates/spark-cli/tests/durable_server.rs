use spark_client::Client;
use spark_crypto::Mnemonic;
use std::{
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
};
struct Server {
    child: Child,
    _output: BufReader<ChildStdout>,
    ports: Vec<String>,
    pin: spark_transport::Pin,
}
impl Server {
    fn start(dir: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_spark"))
            .args(["serve", "0", "0", "0", "--data-dir"])
            .arg(dir)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut ports = Vec::new();
        let pin = loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "server exited before startup"
            );
            let words: Vec<_> = line.split_whitespace().collect();
            if words.len() == 2 {
                if ["keyring", "content", "issuer"].contains(&words[0]) {
                    ports.push(words[1].to_string());
                }
                if words[0] == "pin" {
                    break spark_transport::Pin::parse(words[1]).unwrap();
                }
            }
        };
        assert_eq!(ports.len(), 3);
        Self {
            child,
            _output: output,
            ports,
            pin,
        }
    }
    fn remote(&self) -> spark_net::Remote {
        spark_net::Remote::connect_via(
            &self.ports[0],
            &self.ports[1],
            &self.ports[2],
            &[self.pin],
            spark_transport::Mode::AlwaysOff,
            spark_net::Cover::Off,
            ("127.0.0.1".into(), 0),
        )
        .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
fn killed_server_recovers_accounts_chunks_mint_keys_and_tls_pin() {
    let directory =
        std::env::temp_dir().join(format!("spark-deployment-recovery-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let phrase = Mnemonic::from_entropy(&[91; 32]);
    let mut rng = spark_store::mint::OsRandom;
    let (room, pin) = {
        let server = Server::start(&directory);
        let mut client = Client::from_mnemonic(&phrase, server.remote()).unwrap();
        let room = client.create_room(&mut rng, "durable").unwrap();
        client.send(&mut rng, room, b"before kill").unwrap();
        // A second process must not load stale in-memory key registries over the same files.
        let duplicate = Command::new(env!("CARGO_BIN_EXE_spark"))
            .args(["serve", "0", "0", "0", "--data-dir"])
            .arg(&directory)
            .output()
            .unwrap();
        assert!(!duplicate.status.success());
        assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already in use"));
        (room, server.pin)
    };
    {
        let server = Server::start(&directory);
        assert_eq!(server.pin, pin);
        let mut client = Client::from_mnemonic(&phrase, server.remote()).unwrap();
        assert_eq!(client.sync(room, 3).unwrap()[0].body, b"before kill");
        client.send(&mut rng, room, b"after restart").unwrap();
        let messages = client.sync(room, 3).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1].body, b"after restart");
    }
    std::fs::remove_dir_all(directory).unwrap();
}
