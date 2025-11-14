    use serde_json;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[derive(serde::Deserialize, Debug)]
    struct Metadata {
        file_id: u64,
    }


    fn handle_encrypted_msg(mut stream: &mut TcpStream, saved_encrypted_files: &mut HashMap<u64, Vec<u8>>) -> std::io::Result<()> {


    
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

        saved_encrypted_files.insert(file_id, ciphertext_bytes);

        println!("Successfully received encrypted file {} from client\n\n", file_id);

        // Spara {file_id: ciphertext_bytes} på nåt smart sätt

        // Spara i merkelträd!

        // add to merkelträd

        // eller hämta från merkelträd

        Ok(())
    }


    fn handle_file_request(stream: &mut TcpStream, saved_encrypted_files: &HashMap<u64, Vec<u8>>) -> std::io::Result<()> {

        let mut file_id_buf  = [0u8; 8];

        stream.read_exact(&mut file_id_buf)?;
        let file_id = u64::from_be_bytes(file_id_buf);

        let encrypted_file = match saved_encrypted_files.get(&file_id) {
            Some(f) => f,
            None => {
                // Send error: prefix 0 = file not found
                stream.write_all(&[0])?;
                return Ok(());
            }
        };

        stream.write_all(&[2])?;

        let len = encrypted_file.len() as u32;
        stream.write_all(&len.to_be_bytes())?;

        stream.write_all(&encrypted_file)?;

        stream.flush()?; 

        println!("Sending encrypted file {} bytes", encrypted_file.len());
        println!("Sent encrypted file {file_id} to client");

        Ok(())
    }


    fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {

        let mut saved_encrypted_files: HashMap<u64, Vec<u8>> = HashMap::new();


        loop {
            let mut prefix_buf = [0u8; 1];

            stream.read_exact(&mut  prefix_buf)?;
            let prefix = prefix_buf[0];
            

            match prefix {

                1 => {
                    println!("Handling encrypted file...");
                    handle_encrypted_msg(&mut stream, &mut saved_encrypted_files)
                },

                2 => {
                    println!("Handling file request...");
                    handle_file_request(&mut stream, &saved_encrypted_files)
                }
                
                _ => break,
            
            }?;
        }

        Ok(())
    }

    fn main() -> std::io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to listen on port --");
        println!("Listening on port --");

        // skapa tomt merkelträd?

        for stream in listener.incoming() {
            handle_client(stream?)?;
        }

        Ok(())
    }
