use hmac::{Hmac, Mac};
use sha2::Sha256;

struct Private<'a> {
    key: &'a [u8],
    counter: u64,
}

#[derive(Debug)]
enum ReceiveError {
    BadKey,
    BadSignature,
}

impl<'a> Private<'a> {
    fn new(key: &'a [u8]) -> Self {
        Private {
            key,
            counter: <u64>::MIN,
        }
    }

    fn bump(&mut self) {
        self.counter = self.counter.wrapping_add(1);
    }
}

fn send_message(p: &Private<'_>, message: &[u8]) -> Result<Vec<u8>, hmac::digest::InvalidLength> {
    let mut mac = Hmac::<Sha256>::new_from_slice(p.key)?;
    mac.update(message);
    mac.update(&p.counter.to_le_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn receive_message(
    p: &mut Private<'_>,
    message: &[u8],
    authentication_tag: &[u8],
) -> Result<(), ReceiveError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(p.key).map_err(|_| ReceiveError::BadKey)?;
    mac.update(message);
    mac.update(&p.counter.to_le_bytes());

    match mac.verify(authentication_tag.into()) {
        Ok(()) => {
            p.bump();
            Ok(())
        }
        Err(_) => Err(ReceiveError::BadSignature),
    }
}

fn main() {
    let message = "Hello how are you".as_bytes();
    let secret = "this-should-be-super-long-and-very-secret-key-noone-can-guess".as_bytes();

    let mut p = Private::new(secret);

    match send_message(&p, message) {
        Ok(tag) => {
            // Should succeed
            println!("First: {:?}", receive_message(&mut p, message, &tag[..]));

            // This replay should fail
            println!("Replay: {:?}", receive_message(&mut p, message, &tag[..]));
        }
        Err(err) => {
            eprint!("{:?}", err);
        }
    }

    match send_message(&p, message) {
        Ok(tag) => {
            println!("Resent: {:?}", receive_message(&mut p, message, &tag[..]));
        }
        Err(err) => {
            eprint!("{:?}", err);
        }
    }
}
