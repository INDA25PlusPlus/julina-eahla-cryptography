use std::io::{Read, Write};
use std::net::TcpStream;

use aes_gcm::aes::cipher;
use aes_gcm::{
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use std::fs;
use std::path::Path;

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

    stream.write(&[1])?;

    let msg_package = stream.read(&mut [0; 128])?;
    println!("{}", msg_package);

    // create encryption key -- same used througout
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let file_id = 0;

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::{
        env,
        fs::{File, remove_file},
        time::Instant,
    };

    #[test]
    fn test_encryption_gcm() {
        let t_total = Instant::now(); //tidtagning
        let key = Aes256Gcm::generate_key(OsRng);

        let cipher = Aes256Gcm::new(&key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, b"Hello World!".as_ref()).unwrap();

        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        let elapsed_total = t_total.elapsed();

        assert_eq!(String::from_utf8(plaintext).unwrap(), "Hello World!");
        print!("Time elapsed. total: {:#?} ", elapsed_total); //tidtagning
    }

    #[test]
    fn test_build_plaintext() {
        let t_total = Instant::now(); //time
        //create test file
        let file = "test_file.txt";
        let mut test_file = File::create(&file).unwrap();
        test_file.write_all(b"Hello World!").unwrap();
        let full_path = env::current_dir().unwrap().join(file);

        let t_func = Instant::now();
        let test = build_plaintext(full_path.to_str().unwrap()).unwrap(); //test function
        let elapsed_func = t_func.elapsed();

        remove_file(full_path).unwrap();
        let elapsed_total = t_total.elapsed();

        assert_eq!(
            test,
            [
                &(13u16).to_be_bytes()[..], //len of filename (test_file.txt is 13)
                b"test_file.txt",           //filename
                b"Hello World!"             //contents
            ]
            .concat()
        );
        print!(
            "Time elapsed. total: {:#?} function: {:#?} ",
            elapsed_total, elapsed_func
        );
    }
    #[test]
    fn test_endecrypt() {
        let t_total = Instant::now();
        //create test file
        let file = "test_file.txt";
        let mut test_file = File::create(&file).unwrap();
        test_file.write_all(b"Hello World!").unwrap();
        let full_path = env::current_dir().unwrap().join(file);

        let key = Aes256Gcm::generate_key(OsRng);
        let cipher = Aes256Gcm::new(&key);

        let t_encrypt = Instant::now(); //time

        let encrypted = encrypt_file(&cipher, full_path.to_str().unwrap());

        let elapsed_encrypt = t_encrypt.elapsed(); //time
        let t_decrypt = Instant::now(); //time

        let decrypted = decrypt_file(&cipher, encrypted);

        let elapsed_decrypt = t_decrypt.elapsed(); //time
        let elapsed_total = t_total.elapsed(); //time

        assert_eq!(
            decrypted,
            ("test_file.txt".to_string(), b"Hello World!".to_vec())
        );
        print!(
            "Time elapsed. total: {:#?} encrypt: {:#?} decrypt: {:#?} ",
            elapsed_total, elapsed_encrypt, elapsed_decrypt
        );
    }
}
