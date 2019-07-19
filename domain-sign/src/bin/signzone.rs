//! Signs a zone file.

use std::io;
use std::convert::TryFrom;
use std::fs::File;
use domain_core::{Dname, Record, Serial};
use domain_core::rdata::MasterRecordData;
use domain_core::master::reader::{Reader, ReaderItem};
use domain_sign::openssl;
use domain_sign::key::StoredKey;
use domain_sign::sign::{FamilyName, SortedRecords};
use unwrap::unwrap;


fn main() {
    let mut args = std::env::args();
    let _ = unwrap!(args.next());
    let (keyfile, infile) = match (args.next(), args.next()) {
        (Some(keyfile), Some(infile)) => (keyfile, infile),
        _ => {
            eprintln!("Usage: signzone <keyfile> <infile> [<outfile>]");
            std::process::exit(1)
        }
    };
    let outfile = args.next();

    if let Err(err) = sign_zone(keyfile, infile, outfile) {
        eprintln!("{}", err);
        std::process::exit(1)
    }
        
}


type Records = SortedRecords<Dname, MasterRecordData<Dname>>;


fn sign_zone(
    keyfile: String, infile: String, outfile: Option<String>
) -> Result<(), io::Error> {
    let mut key = openssl::Key::try_from(StoredKey::load(&keyfile)?)?;
    key.set_flags(257);

    let mut records = load_zone(infile)?;
    let (apex, ttl) = find_apex(&records)?;
    match apex.dnskey(ttl, &key) {
        Ok(record) => {
            let _ = records.insert(Record::from_record(record));
        }
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Creating DNSKEY record failed."
            ))
        }
    }
    let nsecs = records.nsecs(&apex, ttl);
    records.extend(nsecs.into_iter().map(Record::from_record));
    let inception = Serial::now().sub(10);
    let expiration = inception.add(2592000); // XXX 30 days
    let rrsigs = match records.sign(&apex, expiration, inception, &key) {
        Ok(rrsigs) => rrsigs,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Signing failed."
            ))
        }
    };
    records.extend(rrsigs.into_iter().map(Record::from_record));
    let _ds = match apex.ds(ttl, key) {
        Ok(ds) => ds,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Creating DS record failed."
            ))
        }
    };

    match outfile {
        Some(path) => {
            let mut file = File::create(path)?;
            records.write(&mut file)?;
        }
        None => {
            {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                records.write(&mut stdout)?;
            }
            println!("");
        }
    }
    //println!("{}", ds);
    Ok(())
}


fn load_zone(infile: String) -> Result<Records, io::Error> {
    let reader = Reader::open(infile)?;
    let mut res = SortedRecords::new();
    for item in reader {
        match item {
            Ok(ReaderItem::Record(record)) => {
                let _ = res.insert(record);
            }
            Ok(ReaderItem::Include {..}) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "$include not supported"
                ))
            }
            Ok(ReaderItem::Control {name, ..}) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("${} not supported", name)
                ))
            }
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{}", err)
                ))
            }
        }
    }
    Ok(res)
}

fn find_apex(
    records: &Records
) -> Result<(FamilyName<Dname>, u32), io::Error> {
    let soa = match records.find_soa() {
        Some(soa) => soa,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot find SOA record"
            ))
        }
    };
    let ttl = match *soa.first().data() {
        MasterRecordData::Soa(ref soa) => soa.minimum(),
        _ => unreachable!()
    };
    Ok((soa.family_name().to_name(), ttl))
}

