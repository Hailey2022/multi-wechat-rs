use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;

use crate::winapi::*;

#[inline(always)]
pub fn get_last_error() -> io::Error {
    io::Error::last_os_error()
}

pub fn get_install_path(name: &str) -> Option<String> {
    let mut hkey: HKEY = null_mut();

    let result = unsafe {
        RegOpenKeyExA(
            HKEY_CURRENT_USER,
            CString::new(name).ok()?.as_ptr() as _,
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        )
    };

    if result != 0 {
        eprintln!("reg open error: {} [{}]", get_last_error(), result);
        return None;
    }

    let skey = "InstallPath";

    let mut buf = [0; MAX_PATH + 1];
    let mut bsize = 0;

    let _ = unsafe {
        RegQueryValueExA(
            hkey,
            CString::new(skey).ok()?.as_ptr() as _,
            null_mut(),
            null_mut(),
            buf.as_mut_ptr() as _,
            &mut bsize,
        )
    };
    let result = unsafe {
        RegQueryValueExA(
            hkey,
            CString::new(skey).ok()?.as_ptr() as _,
            null_mut(),
            null_mut(),
            buf.as_mut_ptr() as _,
            &mut bsize,
        )
    };

    if result != 0 {
        unsafe { RegCloseKey(hkey) };

        eprintln!("reg query value error: {} [{}]", get_last_error(), result);
        return None;
    }
    unsafe { RegCloseKey(hkey) };

    bsize -= 1;

    Some(char_to_string(&buf[..(bsize as _)]))
}

pub fn wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn utf16_to_string(s: &UNICODE_STRING) -> String {
    unsafe {
        String::from_utf16(std::slice::from_raw_parts(s.Buffer, (s.Length / 2) as _)).unwrap()
    }
}

pub fn char_to_string(chars: &[i8]) -> String {
    chars.into_iter().map(|c| *c as u8 as char).collect()
}

pub fn wchar_to_string(slice: &[u16]) -> String {
    match slice.iter().position(|&x| x == 0) {
        Some(pos) => OsString::from_wide(&slice[..pos])
            .to_string_lossy()
            .into_owned(),
        None => OsString::from_wide(slice).to_string_lossy().into_owned(),
    }
}

pub fn evelate_privileges() -> Result<(), io::Error> {
    let mut htk: HANDLE = null_mut();
    let mut tkp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Attributes: SE_PRIVILEGE_ENABLED,
            ..Default::default()
        }],
    };
    if FALSE
        == unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut htk,
            )
        }
    {
        println!("open process token failed");
        return Err(get_last_error());
    }

    if FALSE
        == unsafe {
            LookupPrivilegeValueA(
                null_mut(),
                CString::new(SE_DEBUG_NAME)?.as_ptr() as _,
                &mut tkp.Privileges[0].Luid,
            )
        }
    {
        println!("lookup privilege value failed");
        return Err(get_last_error());
    }

    if FALSE == unsafe { AdjustTokenPrivileges(htk, FALSE, &mut tkp, 0, null_mut(), null_mut()) } {
        println!("adjust token privilege failed");
        return Err(get_last_error());
    }

    Ok(())
}

pub fn create_process(target: &str) -> Result<(), io::Error> {
    let path = wide_string(target);
    let mut si = std::mem::MaybeUninit::zeroed();
    let mut pi = std::mem::MaybeUninit::zeroed();

    if FALSE
        == unsafe {
            CreateProcessW(
                path.as_ptr() as _,
                null_mut(),
                null_mut(),
                null_mut(),
                FALSE,
                CREATE_NEW_CONSOLE,
                null_mut(),
                null_mut(),
                si.as_mut_ptr(),
                pi.as_mut_ptr(),
            )
        }
    {
        println!("create process {} failed.", target);
        return Err(get_last_error());
    }

    Ok(())
}

pub fn show_message_box(caption: &str, text: &str) {
    unsafe {
        MessageBoxW(
            null_mut() as _,
            wide_string(text).as_ptr() as _,
            wide_string(caption).as_ptr() as _,
            MB_OK,
        );
    }
}
