use std::{process::ExitCode, thread, time};
use aes::{Aes128, cipher::{KeyInit, BlockDecrypt, BlockEncrypt}};
use base64::Engine;
use clap::{Arg, Command, ArgAction};
use magic_crypt::generic_array::GenericArray;
use pnet::datalink;
use std::net::UdpSocket;
use typenum::U16;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GENERIC_KEY: &[u8] = b"a3K8Bx%2r8Y7#xDh";

struct ScanResult {
  ip: String,
  mac: String
}

fn main() -> ExitCode {
  let cli = Command::new("Grees")
  .about("proper use of your air-conditioner")
  .version(VERSION)
  .author("DepriSheep")
  .subcommand_required(true)
  .arg_required_else_help(true)
  .subcommand(
    Command::new("maintain")
    .about("Maintain a certain temperature in your room.")
    .arg(
      Arg::new("temperature")
      .short('t')
      .long("temperature")
      .required(true)
      .action(ArgAction::Set)
      .num_args(1)
    )
    .arg(
      Arg::new("cooling")
      .long("cooling")
      .help("Use cooling to achieve the temperature.")
      .required(false)
      .action(ArgAction::SetTrue)
    )
    .arg(
      Arg::new("heating")
      .long("heating")
      .help("Use heating to achieve the temperature.")
      .required(false)
      .action(ArgAction::SetTrue)
    )
  )
  .arg(
    Arg::new("ipaddress")
    .short('i')
    .long("ipaddress")
    .help("The IP address of the device in your home network.")
    .required(true)
    .action(ArgAction::Set)
  )
  .get_matches();

  match cli.subcommand() {
    Some(("maintain", args)) => {
      let ip = cli.get_one::<String>("ipaddress").unwrap().to_string();
      let temp = if args.get_one::<String>("temperature").is_some()
      {
        args.get_one::<String>("temperature").unwrap().parse::<f32>().unwrap()
      }
      else
      {
        eprintln!("Your temperature must be an unsigned 32bit integer.");
        return ExitCode::FAILURE;
      };
      let cooling = args.get_one::<bool>("cooling").unwrap();
      let heating = args.get_one::<bool>("heating").unwrap();

      if !cooling && !heating {
        eprintln!("You have to activate either cooling or heating or both.");
        return ExitCode::FAILURE;
      }
      
      let search = search_in_all_interfaces(&ip);
      let mac = if search.is_some() {
        search.unwrap()
      } else {
        eprintln!("Device doesn't respond.");
        return ExitCode::FAILURE;
      };

      if let Some(data) = bind_device(&ip, &mac) {
        let key = data["key"].to_string().replace("\"", "");
        maintain(&ip, &mac, key.as_bytes(), &temp, *cooling, *heating);
      } else {
        println!("Failed binding to device.");
      }
    },
    _ => unreachable!()
  }
  return ExitCode::SUCCESS
}

fn maintain(ip: &String, mac: &String, key: &[u8], temp: &f32, cooling: bool, heating: bool) {
  let mut last_command = time::SystemTime::now()-time::Duration::from_secs(300);
  loop {
    let (current_temp, status) = get_temp_power(ip, mac, &key).unwrap();
    if ((current_temp+2.0 < *temp) && heating && !status) ||
    ((current_temp-2.0 > *temp) && cooling && !status) {
      if time::SystemTime::now() > last_command+time::Duration::from_secs(310) {
        println!("Turning AC ON!");
        set_power(true, ip, mac, key);
        last_command = time::SystemTime::now();
      } else {
        println!("Would've turned the AC ON, but the last action is less than 5min ago!");
      }
    } else if status {
      if time::SystemTime::now() > last_command+time::Duration::from_secs(310) {
        println!("Turning AC OFF!");
        set_power(false, ip, mac, key);
        last_command = time::SystemTime::now();
      } else {
        println!("Would've turned the AC OFF, but the last action is less than 5min ago!");
      }
    } else {
      println!("Temperature is fine. Not sending anything.")
    }

    thread::sleep(std::time::Duration::from_secs(300));
  }
}

fn set_power(on: bool, ip: &String, mac: &String, key: &[u8]) {
  let pack = format!("{{\"opt\": [\"Pow\"], \"p\": [{}], \"t\": \"cmd\"}}", if on {1} else {0});
  let encrypted = encrypt(&pack, Some(key));
  let data = prepare_pack(encrypted, mac, String::from("0"));
  send_to_gree(ip, data.as_bytes()).unwrap();
}

fn get_temp_power(ip: &String, mac: &String, key: &[u8]) -> Option<(f32, bool)> {
  let pack = format!("{{\"cols\":[\"Pow\", \"TemSen\"],\"mac\":\"{}\",\"t\":\"status\"}}", mac);
  let encrypted = encrypt(&pack, Some(key));
  let data = prepare_pack(encrypted, mac, String::from("0"));
  if let Ok(res) = send_to_gree(ip, data.as_bytes()) {
    let data = decrypt(&res["pack"].as_str().unwrap(), Some(key));
    return Some((data["dat"][1].to_string().parse::<f32>().unwrap()-40.0,
    if data["dat"][0].as_u64().unwrap() == 0 {false} else {true}));
  }
  None
}

fn bind_device(ip: &String, mac: &String) -> Option<serde_json::Value> {
  let pack = format!("{{\"mac\":\"{}\", \"t\":\"bind\", \"uid\":0}}", mac);
  let encrypted = encrypt(&pack, None);
  let data = prepare_pack(encrypted, mac, String::from("1"));
  if let Ok(res) = send_to_gree(ip, data.as_bytes()) {
    return Some(decrypt(&res["pack"].as_str().unwrap(), None));
  }
  None
}

fn send_to_gree(ip: &String, data: &[u8]) -> Result<serde_json::Value, ()> {
  let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to socket.");
  socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("Failed to set timeout.");
  socket.send_to(data, format!("{}:7000", ip)).expect("Failed to send request.");
  
  let mut buf = [0u8; 1024];
  loop {
    match socket.recv_from(&mut buf) {
      Ok((size, _)) => {
        let data = &buf[..size];
        if data.is_empty() {
          continue;
        }
        if let Ok(json) = serde_json::from_slice(data) {
          return Ok(json);
        } else {
          return Err(());
        };
      }
      Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
        println!("WouldBlock");
        continue;
      }
      Err(err) => {
        println!("{}", err);
        return Err(());
      }
    }
  }
}

fn prepare_pack(encrypted_pack: String, mac: &String, i: String) -> String {
  format!("{{\"cid\": \"app\", \"i\": {}, \"pack\": \"{}\", \"t\": \"pack\", \"tcid\": \"{}\", \"uid\": 0}}", i, encrypted_pack, mac)
}

fn search_device(broadcast: String) -> Vec<ScanResult> {
  let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to socket.");
  socket.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("Failed to set timeout.");
  socket.set_broadcast(true).expect("Failed to set SO_BROADCAST.");
  socket.send_to(b"{\"t\":\"scan\"}", format!("{}:7000", broadcast)).expect("Failed to send scan message.");
  let mut results = Vec::new();
  let mut buffer = [0u8; 1024];

  loop {
    match socket.recv_from(&mut buffer) {
      Ok((size, addr)) => {
        let data = &buffer[..size];
        if data.is_empty() {
          continue;
        }
        let raw_json = &data[0..data.iter().rposition(|&x| x == b'}').map(|pos| pos + 1).unwrap_or(0)];
        let resp: serde_json::Value = serde_json::from_slice(raw_json).expect("Failed to parse JSON response");
        let pack_encoded = resp["pack"].as_str().expect("Missing 'pack' field").to_owned();
        let pack_decrypted = decrypt(&pack_encoded, None);
        results.push(ScanResult{ip: addr.ip().to_string(), mac: pack_decrypted["mac"].as_str().unwrap().to_owned()});
      }
      Err(_) => {
        println!("Search finished, found {} device(s)", results.len());
        break;
      }
    }
  }
  results
}

fn decrypt(pack_encoded: &str, key_: Option<&[u8]>) -> serde_json::Value {
  let key = if key_.is_some() {
    GenericArray::clone_from_slice(key_.unwrap())
  } else {
    GenericArray::clone_from_slice(GENERIC_KEY)
  };
  let base64_bytes = base64::engine::general_purpose::STANDARD.decode(pack_encoded).expect("Base64 failed");
  let mut blocks = Vec::new();
    (0..base64_bytes.len()).step_by(16).for_each(|x| {
    blocks.push(GenericArray::clone_from_slice(&base64_bytes[x..x + 16]));
  });
  let cipher = Aes128::new(&key);
  cipher.decrypt_blocks(&mut blocks);
  let pack_decrypted: String = blocks.iter().flatten().map(|&x| x as char).collect();
  let modified_string = pack_decrypted.trim_end_matches('\u{3}');
  let modified_string = modified_string.trim_end_matches('\u{c}');
  let modified_string = modified_string.trim_end_matches('\u{e}');
  let modified_string = modified_string.trim_end_matches('\u{6}');
  let pack: serde_json::Value = serde_json::from_str(modified_string).expect("Failed to parse JSON response");
  return pack;
}

fn encrypt(data: &str, key_: Option<&[u8]>) -> String {
  let key = if key_.is_some() {
    GenericArray::clone_from_slice(key_.unwrap())
  } else {
    GenericArray::clone_from_slice(GENERIC_KEY)
  };
  let chunk_size = 16;
  let data_bytes = data.bytes().collect::<Vec<u8>>();
  let num_blocks = (data_bytes.len() + chunk_size - 1) / chunk_size;
  let padded_size = num_blocks * chunk_size;
  let mut blocks: Vec<GenericArray<u8, U16>> = data_bytes
    .chunks_exact(chunk_size)
    .chain(std::iter::once(&data_bytes[chunk_size * (num_blocks - 1)..]))
    .map(|chunk| {
        let mut block = GenericArray::default();
        block[..chunk.len()].clone_from_slice(chunk);
        block
    })
    .collect();
  let last_block = blocks.last_mut().unwrap();
  for i in data_bytes.len()..padded_size {
    last_block[i % chunk_size] = 0;
  }
  let cipher = Aes128::new(&key);
  cipher.encrypt_blocks(&mut blocks);
  let encrypted_bytes: Vec<u8> = blocks.into_iter().flatten().collect();
  base64::engine::general_purpose::STANDARD.encode(encrypted_bytes)
}

fn search_in_all_interfaces(ip: &String) -> Option<String> {
  for interface in datalink::interfaces() {
    if interface.is_up() && !interface.ips.is_empty() && !interface.is_loopback() {
      for ip_network in &interface.ips {
        if ip_network.is_ipv6() {
          continue;
        }
        let broadcast = ip_network.broadcast().to_string();
        for dev in search_device(broadcast) {
          if &dev.ip == ip {
            return Some(dev.mac);
          }
        }
      }
    }
  }
  None
}
