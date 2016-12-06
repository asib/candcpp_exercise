extern crate byteorder;

use std::env;
use std::fs::{OpenOptions,File};
use std::io;
use std::io::{SeekFrom,Cursor};
use std::io::prelude::*;
use byteorder::{NetworkEndian,ReadBytesExt};

const MIN_IHLEN: u8 = 5;

struct IPHeader {
    ihlen: u8,
    total_len: u16,
    src_addr: Address,
    dst_addr: Address
}

impl IPHeader {
    fn read_from(f: &mut File) -> std::result::Result<IPHeader,IPHeaderError> {
        let mut h = IPHeader{ihlen: 0, total_len: 0, src_addr: Address::zero(),
            dst_addr: Address::zero()};
        let bytes: Vec<u8> = f.bytes()
            .take(20)
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect();

        // We've just reached the end of the file, no error.
        if bytes.len() == 0 {
            return Err(IPHeaderError::EOF);
        } else if bytes.len() != 20 { // We've partially read a header, this is an error.
            return Err(IPHeaderError::UnexpectedEOF);
        }

        h.ihlen = 0x0f & bytes[0];
        h.total_len = Cursor::new(&bytes[2..4]).read_u16::<NetworkEndian>().unwrap();
        h.src_addr = Address::from_slice(&bytes[12..16]);
        h.dst_addr = Address::from_slice(&bytes[16..20]);

        if h.ihlen > MIN_IHLEN {
            f.seek(SeekFrom::Current(4*(h.ihlen - MIN_IHLEN) as i64))
             .expect("Couldn't seek past IP header");
        }

        Ok(h)
    }
}

enum IPHeaderError {
    EOF,
    UnexpectedEOF
}

impl std::fmt::Display for IPHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", match self {
            &IPHeaderError::EOF => "EOF",
            &IPHeaderError::UnexpectedEOF => "UnexpectedEOF"
        })
    }
}

const MIN_DATA_OFFSET: u8 = 5;

struct TCPHeader {
    data_offset: u8
}

impl TCPHeader {
    fn read_from(f: &mut File) -> io::Result<TCPHeader> {
        let mut h = TCPHeader{data_offset: 0};
        let mut buf = [0; 20];

        try!(f.read_exact(&mut buf));

        h.data_offset = (0xf0 & buf[12]) >> 4;

        if h.data_offset > MIN_DATA_OFFSET {
            f.seek(SeekFrom::Current(4*(h.data_offset - MIN_DATA_OFFSET) as i64))
             .expect("Couldn't seek past TCP header");
        }

        Ok(h)
    }
}

struct Address(u8, u8, u8, u8);

impl Address {
    fn zero() -> Address { Address(0,0,0,0) }

    fn from_slice(buf: &[u8]) -> Address {
        Address(buf[0],buf[1],buf[2],buf[3])
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0, self.1, self.2, self.3)
    }
}

fn write_data(fin: &mut File, len: usize, fout: &mut File) -> io::Result<()> {
    let mut buf = vec![0; len];
    try!(fin.read_exact(&mut buf));
    try!(fout.write_all(&buf));
    Ok(())
}

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

    let mut iph: IPHeader;
    let mut tcph: TCPHeader;

    loop {
        match IPHeader::read_from(&mut fin) {
            Ok(h) => iph = h,
            Err(IPHeaderError::EOF) => break,
            Err(e) => { println!("Couldn't read IP header: {}", e); return }
        };
        match TCPHeader::read_from(&mut fin) {
            Ok(h) => tcph = h,
            Err(e) => { println!("Couldn't read TCP header: {}", e); return }
        };

        let data_len = iph.total_len - 4*iph.ihlen as u16 - 4*tcph.data_offset as u16;
        if data_len > 0 {
            write_data(&mut fin, data_len as usize, &mut fout).expect("Couldn't write data");
        }
    }

    match fout.flush() {
        Ok(()) => return,
        Err(e) => println!("Couldn't flush output: {}", e)
    };
}
