use std::io;
use std::io::{Error, ErrorKind};
use std::ptr::null_mut;
use std::slice;
use crate::utils::*;
use crate::winapi::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub pid: u32,
    pub handle: HANDLE,
    pub type_index: u32,
    pub type_name: String,
    pub name: String,
}

impl Handle {
    pub fn new(handle: HANDLE, pid: u32, type_index: u32, type_name: String, name: String) -> Self {
        Self {
            handle,
            pid,
            type_index,
            type_name,
            name,
        }
    }
}

impl Handle {
    pub fn close_handle(&self) -> Result<(), io::Error> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.pid as _) };
        if process.is_null() {
            return Err(Error::new(ErrorKind::NotFound, "pid"));
        }
        let mut nhe: HANDLE = null_mut();
        let r = unsafe {
            DuplicateHandle(
                process,
                self.handle as _,
                GetCurrentProcess(),
                &mut nhe,
                0,
                FALSE,
                DUPLICATE_CLOSE_SOURCE,
            )
        };
        if r == FALSE {
            println!("duplicate handle to close failed");
            return Err(get_last_error());
        }

        Ok(())
    }
}

pub fn get_system_handles(pid: u32) -> Result<Vec<Handle>, io::Error> {
    let mut buffer_size: usize = 512 * 1024;
    let mut return_len = 0;
    let mut buf: Vec<u8>;

    loop {
        buf = Vec::with_capacity(buffer_size);
        let result = unsafe {
            NtQuerySystemInformation(
                SystemHandleInformation,
                buf.as_mut_ptr() as PVOID,
                buffer_size as u32,
                &mut return_len,
            )
        };

        if NT_SUCCESS(result) {
            break;
        }

        if result != STATUS_INFO_LENGTH_MISMATCH {
            return Err(Error::new(
                ErrorKind::Other,
                format!("[{:#x}] oh no!", result),
            ));
        }

        buffer_size *= 2;
    }

    let hiptr = buf.as_ptr() as *const SYSTEM_HANDLE_INFORMATION;
    let hi = unsafe { &*hiptr };
    let mut handles = Vec::new();
    let raw_handles =
        unsafe { slice::from_raw_parts(hi.Handles.as_ptr(), hi.NumberOfHandles as usize) };
    for he in raw_handles {
        if pid != he.UniqueProcessId as u32 {
            continue;
        }
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, he.UniqueProcessId as _) };
        if process.is_null() {
            continue;
        }
        let mut nhe: HANDLE = null_mut();
        let r = unsafe {
            DuplicateHandle(
                process,
                he.HandleValue as _,
                GetCurrentProcess(),
                &mut nhe,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        unsafe { CloseHandle(process) };
        if r == 0 {
            continue;
        }

        let mut buf = [0u8; 1024];

        let status = unsafe {
            NtQueryObject(
                nhe,
                ObjectNameInformation,
                buf.as_mut_ptr() as _,
                buf.len() as _,
                null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            unsafe { CloseHandle(nhe) };
            continue;
        }
        let name = unsafe { &(&*(buf.as_ptr() as *const OBJECT_NAME_INFORMATION)).Name };
        let name = utf16_to_string(name);

        buf = unsafe { ::std::mem::zeroed() };

        let status = unsafe {
            NtQueryObject(
                nhe,
                ObjectTypeInformation,
                buf.as_mut_ptr() as _,
                buf.len() as _,
                null_mut(),
            )
        };
        if status != STATUS_SUCCESS {
            unsafe { CloseHandle(nhe) };
            continue;
        }
        let type_name = unsafe { &(&*(buf.as_ptr() as *const OBJECT_TYPE_INFORMATION)).TypeName };
        let type_name = utf16_to_string(type_name);

        handles.push(Handle::new(
            he.HandleValue as HANDLE,
            he.UniqueProcessId as u32,
            he.ObjectTypeIndex as u32,
            type_name,
            name,
        ));

        unsafe { CloseHandle(nhe) };
    }

    Ok(handles)
}
