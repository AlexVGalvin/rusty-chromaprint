use bitlab::*;
use base64::prelude::*;
use rustfft::num_traits::ToPrimitive;

const K_NORMAL_BITS: u8 = 3;
const K_MAX_NORMAL_VALUE: u8 = (1 << K_NORMAL_BITS) - 1;

pub(crate) struct FingerprintCompressor{}

impl FingerprintCompressor {
    fn copy_significant_bits(source_vec: &Vec<u8>, output_vec: &mut Vec<u8>, byte_index: u32, bit_index: u32, num_bits: u32) {

        let mut bit_index = bit_index;
        for byte in source_vec {
            output_vec.set(byte_index, bit_index, num_bits, byte >> (8 - num_bits)).unwrap();
            bit_index += num_bits;
        }
    }
    
    fn process_subfingerprint(sub: u32, normal_bits: &mut Vec<u8>, exceptional_bits: &mut Vec<u8>) {
        let mut sub = sub;
        
        let mut bit = 1;
        let mut last_bit = 0;
    
        while sub != 0 {
            if (sub & 1) != 0 {
                let value = bit - last_bit;
    
                if value >= K_MAX_NORMAL_VALUE {
                    normal_bits.push(K_MAX_NORMAL_VALUE);
                    exceptional_bits.push(value - K_MAX_NORMAL_VALUE);
                } else {
                    normal_bits.push(value);
                }
                last_bit = bit;
            }
            sub >>= 1;
            bit += 1;
        }
        normal_bits.push(0);
    }
    
    pub fn compress(raw_fingerprint: &[u32], algorithm: u8) -> String {
        let mut normal_bytes: Vec<u8> = Vec::new();
        let mut exceptional_bytes: Vec<u8> = Vec::new();
    
        let fingerprint_size = raw_fingerprint.len();
        if fingerprint_size != 0 {
            normal_bytes.reserve(fingerprint_size);
            exceptional_bytes.reserve(fingerprint_size/10);
    
            let mut previous = &0u32;
            for current in raw_fingerprint {
                Self::process_subfingerprint(current ^ previous, &mut normal_bytes, &mut exceptional_bytes);
                previous = current;
            }
        }
    
        // compressed chromaprints have a header to indicate the raw fingerprint size and algorithm
        let header_size = 4;
        let normal_bits_size = (normal_bytes.len() * 3 + 7) / 8;
        let exceptional_bits_size = (exceptional_bytes.len() * 5 + 7) / 8;
        let output_size = header_size + normal_bits_size + exceptional_bits_size;
       
    
        let mut output = vec![0u8; output_size];
        // write header
        output[0] = algorithm;
    
        let size_bytes = fingerprint_size.to_le_bytes();
        output[1] = size_bytes[5];
        output[2] = size_bytes[6];
        output[3] = size_bytes[7];
    
        // append 3 MSBs from every normal byte, 5 MSBs from every exceptional byte to the fingerprint
        Self::copy_significant_bits(&normal_bytes, &mut output, 4, 0, 3);
        Self::copy_significant_bits(&exceptional_bytes, &mut output, 4 + normal_bits_size.to_u32().unwrap(), 0, 3);
    
        output.truncate(output_size);
        BASE64_URL_SAFE.encode(output)
    }
    
}


