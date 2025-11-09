
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};


fn handle_client(mut stream: TcpStream) -> std::io::Result<()>  {

    let msg_package = stream.read(&mut [0; 128])?;

    println!("{}", msg_package);

    stream.write(&[1])?;

    Ok(())

}


fn main() -> std::io::Result<()> {

    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to listen on port --");
    println!("Listening on port --");
  
    for stream in listener.incoming() {
        handle_client(stream?);
    }

    Ok(())
}