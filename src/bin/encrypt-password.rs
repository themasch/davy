use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use rpassword::prompt_password;

fn main() {
    let pw = prompt_password("enter password to hash: ").expect("could not read pw");
    let salt = SaltString::generate(&mut OsRng);

    let hasher = Argon2::default();
    let hash = hasher
        .hash_password(pw.as_bytes(), &salt)
        .expect("failed to hash");

    println!("{}", hash);
}
