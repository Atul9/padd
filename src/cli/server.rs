use {
    cli::logger,
    std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process,
        thread,
    },
};

const SERVER_ADDRESS: &str = "127.0.0.1:4774";
const SIG_KILL: &str = "kill\0";
const SIG_CHALLENGE: &str = "lost\0";
const SIG_RESPONSE: &str = "found\0";

pub fn start() {
    logger::info(&format!("Starting padd server on {}", SERVER_ADDRESS));

    match TcpListener::bind(SERVER_ADDRESS) {
        Ok(listener) => {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        thread::spawn(move || {
                            handle_stream(stream);
                        });
                    }
                    Err(err) => logger::err(&format!("Failed to read incoming tcp stream: {}", err))
                }
            }
        }
        Err(err) => logger::fatal(&format!("Failed to bind server: {}", err))
    };
}

fn handle_stream(stream: TcpStream) {
    match stream.try_clone() {
        Ok(mut stream_writer) => {
            let mut buf: Vec<u8> = Vec::new();
            for byte_res in stream.bytes() {
                match byte_res {
                    Ok(byte) => {
                        buf.push(byte);

                        if byte == 0 {
                            break;
                        }
                    }
                    Err(err) => {
                        logger::err(&format!("Failed to read byte from stream: {}", err));
                        return;
                    }
                }
            }

            match String::from_utf8(buf) {
                Ok(string) => match &string[..] {
                    SIG_KILL => process::exit(0),
                    SIG_CHALLENGE => if let Err(err) = stream_writer.write_all(SIG_RESPONSE.as_bytes()) {
                        logger::err(&format!("Failed to write challenge response: {}", err));
                    }
                    &_ => execute_command(string)
                },
                Err(err) => logger::err(&format!(
                    "Failed to convert stream bytes to string: {}", err
                ))
            };
        }
        Err(err) => logger::err(&format!(
            "Failed to clone read stream for writing: {}", err
        ))
    }
}

pub fn kill() {
    if let Ok(mut stream) = TcpStream::connect(SERVER_ADDRESS) {
        if let Err(err) = stream.write_all(SIG_KILL.as_bytes()) {
            logger::err(&format!("Failed to write kill: {}", err));
        }
    }
}

pub fn running() -> bool {
    if let Ok(mut stream) = TcpStream::connect(SERVER_ADDRESS) {
        if let Err(err) = stream.write(SIG_CHALLENGE.as_bytes()) {
            logger::err(&format!("Failed to write challenge: {}", err));
            return false;
        }

        let mut buf = String::new();

        if let Err(err) = stream.read_to_string(&mut buf) {
            logger::err(&format!("Failed to read stream: {}", err));
            return false;
        }

        if buf == SIG_RESPONSE {
            return true;
        }
    }

    false
}

pub fn send_command(mut command: String) {
    command.push('\0');

    match TcpStream::connect(SERVER_ADDRESS) {
        Ok(mut stream) => {
            if let Err(err) = stream.write_all(command.as_bytes()) {
                logger::err(&format!("Failed to send command: {}", err));
            }
        }
        Err(err) => logger::err(&format!("Failed to connect to padd server: {}", err))
    }
}

fn execute_command(command: String) {
    logger::info(&format!("Executing command: {}", &command));
}
