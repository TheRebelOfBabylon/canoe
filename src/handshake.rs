use rand::thread_rng;
use std::net::TcpStream;

use pqc_kyber::*;

struct ClientConn {
    session_key: &[u8; 32],
    conn: TcpStream
}

// client_hand_shake initiates the client connection with the server 
pub fn client_hand_shake(remote_address: String, pk: PublicKey, sk: SecretKey) -> Result<ClientConn> {
    let mut rng = thread_rng();
    // create handshake key
    let (ciphertext, handshake_key) = encapsulate(&pk, &mut rng);
    // Frame { "type": HANDSHAKE_INIT, "payload": ciphertext }
    // establish TCP connection
    // send json encoded frame
    // await response HANDSHAKE_ACK
    // session_key = aes_decrypt
} 