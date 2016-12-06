struct IPHeader {
    ihlen: u8,
    total_len: u16,
    src_addr: Address,
    dst_addr: Address
}

impl IPHeader {
    fn read_from(f: &mut File) -> io::Result<IPHeader> {
        let mut h = IPHeader{ihlen: 0, total_len: 0, src_addr: Address{a:0,b:0,c:0,d:0},
            dst_addr: Address{a:0,b:0,c:0,d:0}};
        let mut buf = [0; 20];
        try!(f.read_exact(&mut buf));

        h.ihlen = buf[1];
        h.total_len = Cursor::new(&buf[2..4]).read_u16::<NetworkEndian>().unwrap();
        h.src_addr = Address::from_slice(&buf[12..16]);
        h.dst_addr = Address::from_slice(&buf[16..20]);

        Ok(h)
    }
}

struct TCPHeader {
    data_offset: u8
}

struct Address {
    a: u8,
    b: u8,
    c: u8,
    d: u8
}

impl Address {
    fn from_slice(buf: &[u8]) -> Address {
        Address{a:buf[0],b:buf[1],c:buf[2],d:buf[3]}
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.a, self.b, self.c, self.d)
    }
}

extern crate byteorder;

use std::env;
use std::fs::{OpenOptions,File};
use std::io;
use std::io::Cursor;
use std::io::prelude::*;
use byteorder::{NetworkEndian,ReadBytesExt};

fn main() {
    if env::args().count() != 3 {
        println!("Usage: extract <fin> <fout>");
        return;
    }

    let mut fin = match File::open(env::args().nth(1).unwrap()) {
        Ok(f) => f,
        Err(e) => { println!("Couldn't open input file: {}", e); return }
    };
    let mut fout = match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(env::args().nth(2).unwrap()) {
        Ok(f) => f,
        Err(e) => { println!("Couldn't open output file: {}", e); return }
    };

    let iph: IPHeader;
    let tcph: TCPHeader;

    match IPHeader::read_from(&mut fin) {
        Ok(h) => iph = h,
        Err(e) => { println!("Couldn't read IP header: {}", e); return }
    };
}
