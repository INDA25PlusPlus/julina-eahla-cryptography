use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[derive(serde::Deserialize, Debug)]
struct Metadata {
    file_id: u32,
}

fn read_tcp_message(mut stream: TcpStream) -> std::io::Result<()> {
    // Format på meddelande:
    // [metadata length: 4 bytes]
    // [metadata JSON]
    // [ciphertext length: 4 bytes]
    // [ciphertext bytes]  <-- encrypted nonce + filename + file content + 16-byte tag
    let mut metadata_len_bytes = [0u8; 4]; // 4 byte buffer
    stream.read_exact(&mut metadata_len_bytes)?;

    let metadata_len = u32::from_be_bytes(metadata_len_bytes);

    let mut metadata_bytes = vec![0u8; metadata_len as usize];
    stream.read_exact(&mut metadata_bytes)?;

    // metadata = {file_id: _, ...}
    let metadata_json = String::from_utf8_lossy(&metadata_bytes);
    let metadata: Metadata = serde_json::from_str(&metadata_json)?;

    let file_id = metadata.file_id;

    let mut ciphertext_len_bytes = [0u8; 4];
    stream.read_exact(&mut ciphertext_len_bytes)?;

    let ciphertext_len = u32::from_be_bytes(ciphertext_len_bytes);

    let mut ciphertext_bytes = vec![0u8; ciphertext_len as usize];
    stream.read_exact(&mut ciphertext_bytes)?;

    // Spara {file_id: ciphertext_bytes} på nåt smart sätt

    Ok(())
}

fn handle_client(stream: TcpStream) -> std::io::Result<()> {
    read_tcp_message(stream)?;

    Ok(())
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to listen on port --");
    println!("Listening on port --");

    for stream in listener.incoming() {
        handle_client(stream?)?;
    }

    Ok(())
}
