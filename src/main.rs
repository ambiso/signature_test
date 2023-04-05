use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey},
    elliptic_curve::rand_core::OsRng,
    PublicKey, pkcs8::EncodePublicKey,
};

fn main() {
    let mut failed = 0;
    let n = 10;
    for _ in 0..n {
        let sk = SigningKey::random(&mut OsRng);
        let msg = b"hello";
        let (signature, v) = sk.sign_recoverable(&msg[..]).unwrap();

        let signature_bytes = signature.to_bytes();
        let recovery_id = v.to_byte();

        let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
        let recovered_vk =
            VerifyingKey::recover_from_msg(&msg[..], &signature, recovery_id.try_into().unwrap())
                .unwrap();

        let pk: PublicKey = recovered_vk.into();
        let vpk = sk.verifying_key().into();
        if pk != vpk {
            dbg!(pk, vpk);
            failed += 1;
        }
    }
    println!(
        "Failure rate: {}/{} = {:.02}%",
        failed,
        n,
        failed as f64 / n as f64 * 100.0
    );
}
