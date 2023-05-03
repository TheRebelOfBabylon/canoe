use std::fs;
use std::io::{Error, ErrorKind};
use std::path::Path;

use pem::parse;
use pqc_kyber::*;

// import_identity_file opens the private key file at the specified path, parses it and returns the parsed result
pub fn import_identity_file(path_to_key: Option<String>) -> Option<SecretKey> {
    match path_to_key {
        Some(path) => {
            // check if file exists
            let b = Path::new(path.as_str()).is_file();
            if !b {
                return None
            }
            // open the file and read contents into PEM struct
            let pem_file = fs::read_to_string(path);
            match pem_file {
                Err(_) => return None,
                _ => (),
            }
            let pem = parse(pem_file.unwrap());
            match pem {
                Err(_) => return None,
                Ok(pem) => {
                    // Check that label is KYBER PRIVATE KEY
                    if pem.tag() != String::from("KYBER PRIVATE KEY") {
                        return None
                    }
                    return Some(pem.into_contents().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KYBER_SECRETKEYBYTES, v.len())))
                }
            }
        },
        None => {
            // let's check $HOME/.canoe for id_kyber
            let home_dir = home::home_dir();
            match home_dir {
                Some(mut home_path) => {
                    home_path.push(".canoe");
                    home_path.push("id_kyber");
                    let b = home_path.as_path().is_file();
                    if !b {
                        return None
                    }
                    // open the file and read contents into PEM struct
                    let pem_file = fs::read_to_string(home_path);
                    match pem_file {
                        Err(_) => return None,
                        _ => (),
                    }
                    let pem = parse(pem_file.unwrap());
                    match pem {
                        Err(_) => {
                            return None
                        },
                        Ok(pem) => {
                            // Check that label is KYBER PRIVATE KEY
                            if pem.tag() != String::from("KYBER PRIVATE KEY") {
                                return None
                            }
                            return Some(pem.into_contents().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KYBER_SECRETKEYBYTES, v.len())))
                        }
                    }
                },
                None => return None
            }
            
        }
    }
}

// import_public_key_file
fn import_public_key_file(path_to_file: String) -> Option<PublicKey> {
    // check if file exists
    let b = Path::new(path_to_file.as_str()).is_file();
    if !b {
        return None
    }
    // open the file and read contents into PEM struct
    let pem_file = fs::read_to_string(path_to_file);
    match pem_file {
        Err(_) => return None,
        _ => (),
    }
    let pem = parse(pem_file.unwrap());
    match pem {
        Err(_) => return None,
        Ok(pem) => {
            // Check that label is KYBER PUBLIC KEY
            if pem.tag() != String::from("KYBER PUBLIC KEY") {
                return None
            }
            return Some(pem.into_contents().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KYBER_PUBLICKEYBYTES, v.len())))
        }
    }
}

// send_file sends a file to the remote server using the given secret key
fn send_file(path_to_file: String, remote_address: String, public_key_file: String, sk: SecretKey) -> Result<(), Error> {
    // try to open public key file
    let pub_key = import_public_key_file(public_key_file);
    match pub_key {
        None => return Err(Error::new(ErrorKind::NotFound, "could not find public key file")),
        Some(pk) => {
            // let client_conn = client_hand_shake(remote_address, pk, sk)
            return Ok(())
        }
    } 
}