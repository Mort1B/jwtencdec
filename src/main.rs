use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{thread, time};

// Three registered claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject
    iat: usize,  // Issued at
    exp: usize,  // Expiration date
    test: String,
}

fn main() {
    // CREATE A JSON WEB TOKEN
    let key = b"supermegasecretkey";
    let my_iat = Utc::now().timestamp();
    // exp date 10 seconds into the future
    let my_exp = Utc::now()
        .checked_add_signed(Duration::seconds(10))
        .expect("invalid timestamp")
        .timestamp();

    // create claims object
    let my_claims = Claims {
        sub: "me@gmail.com".to_owned(),
        iat: my_iat as usize,
        exp: my_exp as usize,
        test: "testmessage".to_owned(),
    };

    // encode the token, passing header, claims object and a key
    let token = match encode(
        &Header::default(),
        &my_claims,
        &EncodingKey::from_secret(key),
    ) {
        Ok(t) => t,
        Err(_) => panic!(),
    };

    println!("Token:\n {}", token);

    // After uncommenting this program will wait for 10 secs so JWT will be invalid and program will panic
    // println!("Waiting");
    // thread::sleep(time::Duration::from_secs(10));

    // DECODING A JWT
    let token_data = match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key),
        &Validation::default(),
    ) {
        Ok(c) => c,
        Err(err) => {
            println!("error {:?}", err.kind());
            panic!();
        }
    };
    println!("\nToken Data:\n {:?}", token_data);
}
