extern crate winapi;
extern crate kernel32;
extern crate socket2;

use std;
use std::mem;
use std::net::IpAddr;
use std::io;
use self::winapi::{AF_UNSPEC, ERROR_SUCCESS, ERROR_BUFFER_OVERFLOW, ULONG, PVOID, DWORD, PCHAR};

pub fn gethostname() -> io::Result<String> {
  const MAX_COMPUTERNAME_LENGTH: usize = 15;

  let mut buf = [0 as winapi::CHAR; MAX_COMPUTERNAME_LENGTH + 1];
  let mut len = buf.len() as u32;

  unsafe {
    if kernel32::GetComputerNameA(buf.as_mut_ptr(), &mut len) == 0 {
      return Err(io::Error::last_os_error());
    };
  }

  let host: Vec<u8> = buf[0..len as usize]
              .iter()
              .map(|&e| e as u8)
              .collect();

  Ok(String::from_utf8_lossy(&host).into_owned())
}

pub struct InterfaceAddress {
  ip: Option<IpAddr>,
  is_loopback: bool
}

impl InterfaceAddress {
  pub fn ip(&self) -> Option<IpAddr> {
    self.ip
  }

  pub fn is_loopback(&self) -> bool {
    self.is_loopback
  }
}

pub fn getifaddrs() -> Vec<InterfaceAddress> {
   getifaddrs_int().unwrap()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SOCKET_ADDRESS {
  lp_sockaddr: *const winapi::SOCKADDR,
  length: winapi::c_int
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IP_ADAPTER_UNICAST_ADDRESS {
  length: ULONG,
  flags: DWORD,
  next: *const IP_ADAPTER_UNICAST_ADDRESS,
  address: SOCKET_ADDRESS
}

// Copied from: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366058(v=vs.85).aspx
#[repr(C)]
#[derive(Clone, Copy)]
struct IP_ADAPTER_ADDRESSES {
  length: ULONG,
  if_index: DWORD,
  next: *const IP_ADAPTER_ADDRESSES,
  adapter_name: PCHAR,
  first_unicast_address: *const IP_ADAPTER_UNICAST_ADDRESS,
}

impl Default for IP_ADAPTER_ADDRESSES {
  fn default() -> Self {
    IP_ADAPTER_ADDRESSES {
      length: 0,
      if_index: 0,
      next: std::ptr::null(),
      adapter_name: std::ptr::null_mut(),
      first_unicast_address: std::ptr::null(),
    }
  }
}

#[link(name="iphlpapi")]
extern "system" {
  fn GetAdaptersAddresses(
    family: ULONG,
    flags: ULONG,
    reserved: PVOID,
    addresses: *const IP_ADAPTER_ADDRESSES,
    size: *mut ULONG)
    -> ULONG;
}

fn getifaddrs_int() -> io::Result<Vec<InterfaceAddress>> {
    let mut buf_len: ULONG = 0;
    let result =
      unsafe {
        GetAdaptersAddresses(
          AF_UNSPEC as u32,
          0,
          std::ptr::null_mut(),
          std::ptr::null_mut(),
          &mut buf_len)
      };

    assert!(result != ERROR_SUCCESS);

    if result != ERROR_BUFFER_OVERFLOW {
      error!("Unexpected GetAdaptersAddresses error: {:#x}", result);
      return Err(io::Error::last_os_error());
    }

    let ipa_size = mem::size_of::<IP_ADAPTER_ADDRESSES>();
    let cnt = (buf_len as usize / ipa_size) + 1;
    info!("ipa_size: {}, cnt: {}, buf_len: {}", ipa_size, cnt, buf_len);
    let mut adapters_addresses_buffer: Vec<IP_ADAPTER_ADDRESSES> = vec![Default::default(); cnt];
    let adapter_addresses_ptr = adapters_addresses_buffer.as_mut_ptr();
    let result =
      unsafe {
        GetAdaptersAddresses(
        AF_UNSPEC as u32,
        0,
        std::ptr::null_mut(),
        adapter_addresses_ptr,
        &mut buf_len as *mut ULONG)
      };

    if result != ERROR_SUCCESS {
      error!("Unexpected GetAdaptersAddresses error: {:#x}", result);
      return Err(io::Error::last_os_error());
    }

    let mut ret = vec![];
    let mut adapter_addresses_ptr = adapters_addresses_buffer.as_ptr();
    while adapter_addresses_ptr != std::ptr::null_mut() {
      let unicast_addresses = unsafe{ get_unicast_addresses((*adapter_addresses_ptr).first_unicast_address) }?;

      for unicast_address in unicast_addresses.iter() {
        ret.push(InterfaceAddress {
          ip: Some(*unicast_address),
          is_loopback: (*unicast_address).is_loopback()
        });
      }

      unsafe{ adapter_addresses_ptr = (*adapter_addresses_ptr).next; }
    }

    Ok(ret)
}

unsafe fn get_unicast_addresses(unicast_addresses_ptr: *const IP_ADAPTER_UNICAST_ADDRESS) -> io::Result<Vec<IpAddr>> {
  let mut target_unicast_addresses = vec![];

  let mut unicast_address_ptr = unicast_addresses_ptr;
  while unicast_address_ptr != std::ptr::null_mut() {
    let socket_address = &(*unicast_address_ptr).address;
    let ipaddr = socket_address_to_ipaddr(socket_address);
    target_unicast_addresses.push(ipaddr);

    unicast_address_ptr = (*unicast_address_ptr).next;
  }

  Ok(target_unicast_addresses)
}

unsafe fn socket_address_to_ipaddr(socket_address: &SOCKET_ADDRESS) -> IpAddr {
  let sockaddr = socket2::SockAddr::from_raw_parts(socket_address.lp_sockaddr as *const _, socket_address.length);

  sockaddr.as_inet()
    .map(|s| IpAddr::V4(*s.ip()))
    .unwrap_or_else(|| IpAddr::V6(*sockaddr.as_inet6().unwrap().ip()))
}
