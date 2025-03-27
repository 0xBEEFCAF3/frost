use std::{collections::BTreeMap, error::Error};

use frost_secp256k1_tr as frost;
use rand::thread_rng;


#[test]
fn sign_key_package() -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();
    let max_signers = 5;
    let min_signers = 3;
    /* KEY GENERATION */
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();
    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        key_packages.insert(identifier, key_package);
    }

    let identifier = key_packages.keys().next().unwrap();
    let key_package = key_packages.get(identifier).unwrap().clone();
    let signature = frost::keys::dkg::attest_to_key_package(key_package, &mut rng)?;

    println!("Signature: {:?}", signature);
    // TODO verify signature

    Ok(())
}