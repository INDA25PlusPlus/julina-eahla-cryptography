use std::collections::HashMap;
use std::net::TcpStream;
use std::io::{stdin, stdout, Read, Write};
use serde_json;

use aes_gcm::aes::cipher;
use aes_gcm::{
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};


fn build_plaintext(file_path: &str) -> std::io::Result<Vec<u8>> {
    let file_content = fs::read(file_path).expect("Failed to read file");
    let full_path = Path::new(file_path);
    let filename = full_path
        .file_name()
        .expect("Invalid file path")
        .to_string_lossy()
        .into_owned();

    let filename_bytes = filename.as_bytes();

    if filename_bytes.len() > u16::MAX as usize {
        panic!("Filename too long");
    }

    let mut plaintext = Vec::new();
    // Format: [ (filname 2 bytes) | (filename bytes) | file_content ]
    plaintext.extend_from_slice(&(filename_bytes.len() as u16).to_be_bytes());

    plaintext.extend_from_slice(filename_bytes);

    plaintext.extend_from_slice(&file_content);

    Ok(plaintext)
}

fn encrypt_file(cipher: &Aes256Gcm, file_path: &str) -> Vec<u8> {
    let formatted_plaintext = build_plaintext(file_path).unwrap();

    // unique nonce for each encryption, 96 bits
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, formatted_plaintext.as_ref())
        .expect("Encryption failed");

    let mut output_vec = nonce.to_vec();
    output_vec.extend_from_slice(&ciphertext);

    return output_vec;
}

#[allow(deprecated)]
fn decrypt_file(cipher: &Aes256Gcm, ciphertext_vec: Vec<u8>) -> (String, Vec<u8>) {
    // first 12 bytes is nonce
    let (nonce_bytes, ciphertext) = ciphertext_vec.split_at(12);

    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(&nonce, ciphertext).unwrap();

    let filename_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;

    let filename_bytes = &plaintext[2..2 + filename_len];
    let filename = String::from_utf8_lossy(filename_bytes).into_owned();

    let file_content = plaintext[2 + filename_len..].to_vec();

    (filename, file_content)
}



fn send_encrypted_file(mut stream: &TcpStream, cipher: &Aes256Gcm, file_path: &str, file_id: u64) -> std::io::Result<()> {

    let encrypted_bytes = encrypt_file(cipher, file_path);
    let encrypted_len = encrypted_bytes.len() as u32;

    let mut metadata = HashMap::new();
    metadata.insert("file_id", file_id);

    let metadata_json = serde_json::to_string(&metadata)?;
    let metadata_bytes = metadata_json.as_bytes();
    let metadata_len = metadata_bytes.len() as u32;

    stream.write_all(&metadata_len.to_be_bytes())?;
    stream.write_all(metadata_bytes)?;
    stream.write_all(&encrypted_len.to_be_bytes())?;
    stream.write_all(&encrypted_bytes)?;

    Ok(())
}

fn client_loop(stream: TcpStream, cipher: &Aes256Gcm) -> std::io::Result<()> {

    let mut file_id: u64 = 0;
    let base_path = PathBuf::from("src/example-files");

    loop {
        let mut input = String::new();
        println!("Enter filename in /example-files to encrypt (eg. example.txt) or \n
                enter file_id to decrypt or enter q / quit to exit"); // Add option to enter file that client wants to retrieve from server

        let _=stdout().flush();
        stdin().read_line(&mut input).expect("Did not enter a correct string");
        let input = input.trim(); 

        if input == "q" || input == "quit" {
            // send some message to server?
            break;
        }


        let file_path = base_path.join(input);

        if !file_path.exists() {
            eprintln!("File not found: {:?}", file_path);
            continue;
        }

        let file_path_str = file_path.to_str().unwrap();

        send_encrypted_file(&stream, &cipher, file_path_str, file_id)?;

        println!("Successfully sent encrypted file {} to server\n\n", file_id);

        file_id += 1;
            
        };

    Ok(())
    }




fn main() -> std::io::Result<()> {
    let mut stream = match TcpStream::connect("127.0.0.1:8080") {
        Ok(stream) => {
            println!("Connected to the server!");
            stream
        }
        Err(_) => {
            println!("Couldn't connect to server...");
            return Ok(());
        }
    };

    // stream.write(&[1])?;

    // let msg_package = stream.read(&mut [0; 128])?;
    // println!("{}", msg_package);

    // create encryption key -- same used througout
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);


    client_loop(stream, &cipher)?;


    Ok(())
}
