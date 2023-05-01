use pem;
use std::fs;
use std::io::{Error, ErrorKind, Write};
use std::path::PathBuf;

use pqc_kyber::*;
use home;

// GenerateKeyPairFiles generates the public/private kyber1024 key pair files in PEM format. 
//fn GenerateKeyPairFiles(path_to_file: Option<String>) -> Result<u8, &str> {
pub fn generate_key_pair_files(path_to_file: Option<String>) -> Result<PathBuf, Error> {
    // Check if path_to_file is None
    let key_file_path = match path_to_file {
        None => {
            let mut home_path = home::home_dir();
            match home_path {
                Some(ref mut path) => path.push(".canoe"),
                None => (),
            };
            home_path
        }, 
        Some(ref x) => Some(PathBuf::from(x)),  
    };
    match key_file_path {
        Some(path) => {
            // println!("key_file_path  = {}", path.to_str().unwrap());
            // make directory if it doesn't exist
            let b: bool = path.as_path().is_dir(); 
            if !b {
                fs::create_dir_all(path.clone())?;
            }
            // generate key pair
            let mut rng = rand::thread_rng();
            let key_pair = keypair(&mut rng);
            // create pk sk files
            let mut pk_path = path.clone();
            pk_path.push("id_kyber");
            let sk_path = pk_path.clone();
            pk_path.set_extension("pub");

            let mut pk_file = fs::File::create(pk_path)?;
            let mut sk_file = fs::File::create(sk_path)?;
            // PEM encode
            let pk_pem = pem::Pem::new("KYBER PUBLIC KEY", key_pair.public.clone());
            let pk_pem_s = pem::encode(&pk_pem);

            let sk_pem = pem::Pem::new("KYBER PRIVATE KEY", key_pair.secret.clone());
            let sk_pem_s = pem::encode(&sk_pem);
            // write PEM encoded key pairs to files
            pk_file.write_all(pk_pem_s.as_bytes())?;
            sk_file.write_all(sk_pem_s.as_bytes())?;
            // change permissions to 0600 
            return Ok(path);
        },
        None => return Err(Error::new(ErrorKind::NotFound, "could not find home directory"))
    }
} 