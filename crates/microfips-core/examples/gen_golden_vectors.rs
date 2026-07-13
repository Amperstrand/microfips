use microfips_core::noise::{self, PUBKEY_SIZE, EPOCH_SIZE};
use hex;

fn main() {
    let init_eph: [u8; 32] = [0x01; 32];
    let init_static: [u8; 32] = [0x11; 32];
    let resp_static: [u8; 32] = [0x22; 32];
    let resp_eph: [u8; 32] = [0xAA; 32];
    let epoch_a: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let epoch_b: [u8; 8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let resp_pub = noise::ecdh_pubkey(&resp_static).unwrap();
    let init_pub = noise::ecdh_pubkey(&init_static).unwrap();

    let (mut init, e_pub_init) = noise::NoiseIkInitiator::new(&init_eph, &init_static, &resp_pub).unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = init.write_message1(&init_pub, &epoch_a, &mut msg1).unwrap();

    let e_init_pub: &[u8; PUBKEY_SIZE] = msg1[..PUBKEY_SIZE].try_into().unwrap();
    let mut resp = noise::NoiseIkResponder::new(&resp_static, e_init_pub).unwrap();
    let (recv_init_pub, recv_epoch_a) = resp.read_message1(&msg1[PUBKEY_SIZE..msg1_len]).unwrap();

    let mut msg2 = [0u8; 128];
    let msg2_len = resp.write_message2(&resp_eph, &epoch_b, &mut msg2).unwrap();

    let recv_epoch_b = init.read_message2(&msg2[..msg2_len]).unwrap();

    let (k1_init, k2_init) = init.finalize();
    let (k1_resp, k2_resp) = resp.finalize();

    println!("=== GOLDEN VECTOR: Noise_IK_secp256k1_ChaChaPoly_SHA256 ===");
    println!("init_static_secret: {}", hex::encode(init_static));
    println!("init_static_pub:    {}", hex::encode(init_pub));
    println!("init_eph_secret:    {}", hex::encode(init_eph));
    println!("init_eph_pub:       {}", hex::encode(e_pub_init));
    println!("resp_static_secret: {}", hex::encode(resp_static));
    println!("resp_static_pub:    {}", hex::encode(resp_pub));
    println!("resp_eph_secret:    {}", hex::encode(resp_eph));
    println!("epoch_a:            {}", hex::encode(epoch_a));
    println!("epoch_b:            {}", hex::encode(epoch_b));
    println!("msg1_noise ({}B):   {}", msg1_len, hex::encode(&msg1[..msg1_len]));
    println!("msg2_noise ({}B):   {}", msg2_len, hex::encode(&msg2[..msg2_len]));
    println!("transport_k1:       {}", hex::encode(k1_init));
    println!("transport_k2:       {}", hex::encode(k2_init));
    println!("keys_match: {}", k1_init == k1_resp && k2_init == k2_resp);
    println!("recv_init_pub:      {}", hex::encode(recv_init_pub));
    println!("recv_epoch_a:       {}", hex::encode(recv_epoch_a));
    println!("recv_epoch_b:       {}", hex::encode(recv_epoch_b));
}
