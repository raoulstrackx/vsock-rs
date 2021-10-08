/*
 * Copyright 2019 fsyncd, Berlin, Germany.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use rand::RngCore;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use std::thread::{self, JoinHandle};
use std::io::Write;
use vsock::{get_local_cid, Std, SockAddr, VsockAddr, VsockListener, VsockStream, VMADDR_CID_HOST, VMADDR_CID_LOCAL};

const TEST_BLOB_SIZE: usize = 1_000_000;
const TEST_BLOCK_SIZE: usize = 5_000;

/// A simple test for the vsock implementation.
/// Generate a large random blob of binary data, and transfer it in chunks over the VsockStream
/// interface. The vm enpoint is running a simple echo server, so for each chunk we will read
/// it's reply and compute a checksum. Comparing the data sent and received confirms that the
/// vsock implementation does not introduce corruption and properly implements the interface
/// semantics.
#[test]
fn test_vsock() {
    let mut rng = rand::thread_rng();
    let mut blob: Vec<u8> = vec![];
    let mut rx_blob = vec![];
    let mut tx_pos = 0;

    blob.resize(TEST_BLOB_SIZE, 0);
    rx_blob.resize(TEST_BLOB_SIZE, 0);
    rng.fill_bytes(&mut blob);

    let stream =
        VsockStream::<Std>::connect(&SockAddr::Vsock(VsockAddr::new(3, 8000))).expect("connection failed");

    while tx_pos < TEST_BLOB_SIZE {
        let written_bytes = stream
            .write(&blob[tx_pos..tx_pos + TEST_BLOCK_SIZE])
            .expect("write failed");
        if written_bytes == 0 {
            panic!("stream unexpectedly closed");
        }

        let mut rx_pos = tx_pos;
        while rx_pos < (tx_pos + written_bytes) {
            let read_bytes = stream.read(&mut rx_blob[rx_pos..]).expect("read failed");
            if read_bytes == 0 {
                panic!("stream unexpectedly closed");
            }
            rx_pos += read_bytes;
        }

        tx_pos += written_bytes;
    }

    let expected = Sha256::digest(&blob);
    let actual = Sha256::digest(&rx_blob);

    assert_eq!(expected, actual);
}

#[test]
fn test_get_local_cid() {
    assert_eq!(get_local_cid().unwrap(), VMADDR_CID_HOST);
}

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    message: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Response {
    message: String,
}

fn handle_connection(stream: &mut VsockStream) {
    let mut buff = [0u8; 100];
    let n = stream.read(&mut buff).unwrap();
    let req: Request = serde_cbor::from_slice(&buff[0..n]).unwrap();
    let resp = Response {
        message: req.message.clone().to_uppercase(),
    };
    stream.write_all(&serde_cbor::ser::to_vec(&resp).expect("serialization error")).unwrap();
}

fn start_server(port: u32) -> (JoinHandle<()>, u32) {
    let listener = VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, port).unwrap();
    let port = if let SockAddr::Vsock(vsock) = listener.local_addr().unwrap() {
        vsock.port()
    } else {
        panic!("Not vsock port");
    };

    let handle = thread::Builder::new().spawn(move || {
        let listener = listener;
        loop {
            let (stream, _addr) = listener.accept().unwrap();
            let _ = thread::Builder::new()
                .spawn(move || {
                    let mut stream = stream;
                    handle_connection(&mut stream);
                });
        }
    }).unwrap();
    (handle, port)
}

fn test_connection(port: u32) {
    let mut client = VsockStream::<Std>::connect_with_cid_port(VMADDR_CID_LOCAL, port).unwrap();
    let req = Request {
        message: "Hello world!".to_string(),
    };
    client.write_all(&serde_cbor::ser::to_vec(&req).unwrap()).unwrap();
    let mut buff = [0u8; 100];
    let n = client.read(&mut buff).unwrap();
    let resp: Response = serde_cbor::from_slice(&buff[0..n]).unwrap();
    println!("send: {:?}", req);
    println!("received: {:?}", resp);
    assert_eq!(resp, Response { message: req.message.to_uppercase() });
}

#[test]
fn test_loopback() {
    let (_server_thread, port) = start_server(3000);
    // Wait until server started
    std::thread::sleep(Duration::from_millis(500));
    test_connection(port);
    test_connection(port);
    test_connection(port);
}
