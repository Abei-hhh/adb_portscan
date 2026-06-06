//! Binary-only Ctrl+C handler. Installs a process-wide handler that flips a shared
//! [`CancellationToken`]. Lives next to `main.rs` so the library never installs
//! global signal state on its consumers.
use std::io::Write;
use std::sync::OnceLock;

use adb_portscan::CancellationToken;

static TOKEN: OnceLock<CancellationToken> = OnceLock::new();

#[cfg(windows)]
pub fn install(token: CancellationToken) {
    let _ = TOKEN.set(token);
    type Dword = u32;
    type Bool = i32;
    type PhandlerRoutine = unsafe extern "system" fn(Dword) -> Bool;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: PhandlerRoutine, add: Bool) -> Bool;
    }

    unsafe extern "system" fn handler(ctrl_type: Dword) -> Bool {
        const CTRL_C_EVENT: Dword = 0;
        const CTRL_BREAK_EVENT: Dword = 1;
        if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT {
            if let Some(t) = TOKEN.get() {
                t.cancel();
            }
            return 1;
        }
        0
    }

    unsafe {
        SetConsoleCtrlHandler(handler, 1);
    }
}

#[cfg(not(windows))]
pub fn install(token: CancellationToken) {
    // Without an external crate we have no portable signal handler.
    // Stash the token anyway so call sites are uniform; default Ctrl+C will terminate.
    let _ = TOKEN.set(token);
}

pub fn token() -> CancellationToken {
    TOKEN
        .get()
        .cloned()
        .unwrap_or_else(CancellationToken::new)
}

#[cfg(windows)]
pub fn wait_any_key(msg: &str) {
    println!("{msg}");
    std::io::stdout().flush().ok();
    #[link(name = "msvcrt")]
    extern "C" {
        fn _getch() -> i32;
    }
    unsafe {
        let _ = _getch();
    }
}

#[cfg(not(windows))]
pub fn wait_any_key(msg: &str) {
    use std::io::Read;
    println!("{msg}");
    std::io::stdout().flush().ok();
    let mut buf = [0u8; 1];
    let _ = std::io::stdin().read(&mut buf);
}
