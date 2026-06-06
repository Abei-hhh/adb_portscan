//! 串行化 stderr 输出，防止多线程并发写入造成行交错。
use std::io::Write;
use std::sync::Mutex;

static STDERR_LOCK: Mutex<()> = Mutex::new(());

pub fn log_line(msg: &str) {
    let _g = STDERR_LOCK.lock().unwrap();
    let mut e = std::io::stderr().lock();
    let _ = writeln!(e, "{msg}");
    let _ = e.flush();
}

#[macro_export]
macro_rules! elog {
    ($($arg:tt)*) => {{
        $crate::output::log_line(&format!($($arg)*));
    }};
}
