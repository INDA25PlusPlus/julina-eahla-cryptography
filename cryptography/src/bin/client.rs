use std::net::TcpStream;
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {


    let mut stream = match TcpStream::connect("127.0.0.1:8080") {

        Ok(stream) => {
            println!("Connected to the server!");
            stream
        } 
        Err(_) => {
            println!("Couldn't connect to server...");
            return Ok(())
        } 
     };

    stream.write(&[1])?;

    let msg_package = stream.read(&mut [0; 128])?;
    println!("{}", msg_package);

    Ok(())

}
