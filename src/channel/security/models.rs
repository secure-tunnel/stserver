use rand::Rng;
use std::env::temp_dir;
use std::panic::resume_unwind;
use std::slice::IterMut;
use std::sync::Arc;
use std::vec::Vec;

const MIXED_MATRIX_T_L: usize = 9;
const MIXED_MATRIX_F_L: usize = 16;
const MIXED_MATRIX_D_L: usize = 18;
const MIXED_BINARY_RANDOM_SIZE: usize = 36;

const MIXED_MATRIX1: [i32; 9] = [4, 6, 0, 3, 0, 2, 7, 8, 0];
const MIXED_MATRIX2: [i32; 9] = [-8, 0, 6, 7, 0, -4, 12, 5, -9];

/*
    交换数据
*/
fn mixed_switchmodel(v: &mut Vec<u8>) {
    let mut t: u8 = 0;
    let len = v.len();
    for i in 0..len / 2 {
        t = v[i];
        v[i] = v[len - 1 - i];
        v[len - 1 - i] = t;
    }
}

fn mixed_xor(v: &mut Vec<u8>) {
    for i in 0..v.len() {
        v[i] = v[i] ^ 0x39;
    }
}

/*
   矩阵计算
*/
fn mixed_matrix_t_refra(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_T_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L..(i + 1) * MIXED_MATRIX_T_L].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[0];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_t_refra(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L + offset..(i + 1) * MIXED_MATRIX_T_L + offset].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[0];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_t_refra_re(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_T_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L..(i + 1) * MIXED_MATRIX_T_L].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[8];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_t_refra_re(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L + offset..(i + 1) * MIXED_MATRIX_T_L + offset].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[8];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_t_row(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_T_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L..(i + 1) * MIXED_MATRIX_T_L].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[2];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_t_row(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L + offset..(i + 1) * MIXED_MATRIX_T_L + offset].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[5];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_t_col(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_T_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L..(i + 1) * MIXED_MATRIX_T_L].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[7];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[6];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_t_col(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_T_L {
        let vtmp = v[i * MIXED_MATRIX_T_L + offset..(i + 1) * MIXED_MATRIX_T_L + offset].to_vec();
        v[i * MIXED_MATRIX_T_L] = vtmp[2];
        v[i * MIXED_MATRIX_T_L + 1] = vtmp[0];
        v[i * MIXED_MATRIX_T_L + 2] = vtmp[1];
        v[i * MIXED_MATRIX_T_L + 3] = vtmp[5];
        v[i * MIXED_MATRIX_T_L + 4] = vtmp[3];
        v[i * MIXED_MATRIX_T_L + 5] = vtmp[4];
        v[i * MIXED_MATRIX_T_L + 6] = vtmp[8];
        v[i * MIXED_MATRIX_T_L + 7] = vtmp[6];
        v[i * MIXED_MATRIX_T_L + 8] = vtmp[7];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_f_refra(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_F_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L..(i + 1) * MIXED_MATRIX_F_L].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[0];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_f_refra(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L + offset..(i + 1) * MIXED_MATRIX_F_L + offset].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[0];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_f_refra_re(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_F_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L..(i + 1) * MIXED_MATRIX_F_L].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[15];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_f_refra_re(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L + offset..(i + 1) * MIXED_MATRIX_F_L + offset].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[15];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_f_row(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_F_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L..(i + 1) * MIXED_MATRIX_F_L].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[3];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_f_row(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L + offset..(i + 1) * MIXED_MATRIX_F_L + offset].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[11];
    }

    v.truncate(actually_len);
}

fn mixed_matrix_f_col(v: &mut Vec<u8>) {
    let actually_len = v.len();
    let mut slen = match v.len() % MIXED_MATRIX_F_L {
        0 => actually_len,
        _ => (actually_len / MIXED_MATRIX_F_L + 1) * MIXED_MATRIX_F_L,
    };

    let offset = 4;
    v.resize(slen, 0);
    for i in 0..slen / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L..(i + 1) * MIXED_MATRIX_F_L].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[14];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[12];
    }
    v.insert(0, (actually_len & 0x0ff) as u8);
    v.insert(0, (actually_len >> 8 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 16 & 0x0ff) as u8);
    v.insert(0, (actually_len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_matrix_f_col(v: &mut Vec<u8>) {
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    // println!("actually len: {}", actually_len);
    let offset = 4;
    for i in 0..(v.len() - offset) / MIXED_MATRIX_F_L {
        let vtmp = v[i * MIXED_MATRIX_F_L + offset..(i + 1) * MIXED_MATRIX_F_L + offset].to_vec();
        v[i * MIXED_MATRIX_F_L] = vtmp[3];
        v[i * MIXED_MATRIX_F_L + 1] = vtmp[0];
        v[i * MIXED_MATRIX_F_L + 2] = vtmp[1];
        v[i * MIXED_MATRIX_F_L + 3] = vtmp[2];
        v[i * MIXED_MATRIX_F_L + 4] = vtmp[7];
        v[i * MIXED_MATRIX_F_L + 5] = vtmp[4];
        v[i * MIXED_MATRIX_F_L + 6] = vtmp[5];
        v[i * MIXED_MATRIX_F_L + 7] = vtmp[6];
        v[i * MIXED_MATRIX_F_L + 8] = vtmp[11];
        v[i * MIXED_MATRIX_F_L + 9] = vtmp[8];
        v[i * MIXED_MATRIX_F_L + 10] = vtmp[9];
        v[i * MIXED_MATRIX_F_L + 11] = vtmp[10];
        v[i * MIXED_MATRIX_F_L + 12] = vtmp[15];
        v[i * MIXED_MATRIX_F_L + 13] = vtmp[12];
        v[i * MIXED_MATRIX_F_L + 14] = vtmp[13];
        v[i * MIXED_MATRIX_F_L + 15] = vtmp[14];
    }

    v.truncate(actually_len);
}

fn mixed_netfestival(v: &mut Vec<u8>) {
    let val = match v.len() > 0x80 {
        true => v.len() ^ 0x80,
        false => v.len(),
    };
    for i in 1..v.len() + 1 {
        if (i & 0x0f) == 0x01
            || (i & 0x0f) == 0x02
            || (i & 0x0f) == 0x06
            || (i & 0x0f) == 0x08
            || i % 6 == 0
            || i % 8 == 0
            || i % 12 == 0
        {
            v[i - 1] ^= val as u8;
        }
    }
}

fn mixed_reversible_matrix_core1(dst: &mut Vec<u8>, src: &Vec<u8>, matrix: &[i32; 9]) {
    let a11 = src[0] as i32;
    let a12 = src[1] as i32;
    let a13 = src[2] as i32;
    let a21 = src[3] as i32;
    let a22 = src[4] as i32;
    let a23 = src[5] as i32;
    let a31 = src[6] as i32;
    let a32 = src[7] as i32;
    let a33 = src[8] as i32;

    let c11 = matrix[0] * a11 + matrix[1] * a21 + matrix[2] * a31;
    let c12 = matrix[0] * a12 + matrix[1] * a22 + matrix[2] * a32;
    let c13 = matrix[0] * a13 + matrix[1] * a23 + matrix[2] * a33;
    let c21 = matrix[3] * a11 + matrix[4] * a21 + matrix[5] * a31;
    let c22 = matrix[3] * a12 + matrix[4] * a22 + matrix[5] * a32;
    let c23 = matrix[3] * a13 + matrix[4] * a23 + matrix[5] * a33;
    let c31 = matrix[6] * a11 + matrix[7] * a21 + matrix[8] * a31;
    let c32 = matrix[6] * a12 + matrix[7] * a22 + matrix[8] * a32;
    let c33 = matrix[6] * a13 + matrix[7] * a23 + matrix[8] * a33;

    dst[0] = (c11 / 100) as u8;
    dst[1] = (c11 % 100) as u8;
    dst[2] = (c12 / 100) as u8;
    dst[3] = (c12 % 100) as u8;
    dst[4] = (c13 / 100) as u8;
    dst[5] = (c13 % 100) as u8;
    dst[6] = (c21 / 100) as u8;
    dst[7] = (c21 % 100) as u8;
    dst[8] = (c22 / 100) as u8;
    dst[9] = (c22 % 100) as u8;
    dst[10] = (c23 / 100) as u8;
    dst[11] = (c23 % 100) as u8;
    dst[12] = (c31 / 100) as u8;
    dst[13] = (c31 % 100) as u8;
    dst[14] = (c32 / 100) as u8;
    dst[15] = (c32 % 100) as u8;
    dst[16] = (c33 / 100) as u8;
    dst[17] = (c33 % 100) as u8;
}

fn mixed_reversible_matrix_core2(dst: &mut Vec<u8>, src: &Vec<u8>, matrix: &[i32; 9]) {
    let a11 = (src[0] * 100 + src[1]) as i32;
    let a12 = (src[2] * 100 + src[3]) as i32;
    let a13 = (src[4] * 100 + src[5]) as i32;
    let a21 = (src[6] * 100 + src[7]) as i32;
    let a22 = (src[8] * 100 + src[9]) as i32;
    let a23 = (src[10] * 100 + src[11]) as i32;
    let a31 = (src[12] * 100 + src[13]) as i32;
    let a32 = (src[14] * 100 + src[15]) as i32;
    let a33 = (src[16] * 100 + src[17]) as i32;

    let c11 = matrix[0] * a11 + matrix[1] * a21 + matrix[2] * a31;
    let c12 = matrix[0] * a12 + matrix[1] * a22 + matrix[2] * a32;
    let c13 = matrix[0] * a13 + matrix[1] * a23 + matrix[2] * a33;
    let c21 = matrix[3] * a11 + matrix[4] * a21 + matrix[5] * a31;
    let c22 = matrix[3] * a12 + matrix[4] * a22 + matrix[5] * a32;
    let c23 = matrix[3] * a13 + matrix[4] * a23 + matrix[5] * a33;
    let c31 = matrix[6] * a11 + matrix[7] * a21 + matrix[8] * a31;
    let c32 = matrix[6] * a12 + matrix[7] * a22 + matrix[8] * a32;
    let c33 = matrix[6] * a13 + matrix[7] * a23 + matrix[8] * a33;

    dst[0] = (c11 / 10) as u8;
    dst[1] = (c12 / 10) as u8;
    dst[2] = (c13 / 10) as u8;
    dst[3] = (c21 / 10) as u8;
    dst[4] = (c22 / 10) as u8;
    dst[5] = (c23 / 10) as u8;
    dst[6] = (c31 / 10) as u8;
    dst[7] = (c32 / 10) as u8;
    dst[8] = (c33 / 10) as u8;
}

fn mixed_reversible_matrix(v: &mut Vec<u8>) {
    let len = v.len();
    let slen = match len % MIXED_MATRIX_T_L == 0 {
        true => len,
        false => (len / MIXED_MATRIX_T_L + 1) * MIXED_MATRIX_T_L,
    };
    v.resize(slen, 0);
    let mut result = Vec::new();
    for i in 0..slen / MIXED_MATRIX_T_L {
        let mut tmp = vec![0; MIXED_MATRIX_D_L];
        mixed_reversible_matrix_core1(
            &mut tmp,
            &v[i * MIXED_MATRIX_T_L..(i + 1) * MIXED_MATRIX_T_L].to_vec(),
            &MIXED_MATRIX1,
        );
        result.append(&mut tmp);
    }
    let result_len = result.len();
    v.clear();
    v.append(&mut result);
    v.insert(0, (len & 0x0ff) as u8);
    v.insert(0, (len >> 8 & 0x0ff) as u8);
    v.insert(0, (len >> 16 & 0x0ff) as u8);
    v.insert(0, (len >> 24 & 0x0ff) as u8);
}

fn mixed_reverse_reversible_matrix(v: &mut Vec<u8>) {
    let len = v.len();
    let actually_len = (((v[0] & 0xff) as usize) << 24)
        | (((v[1] & 0xff) as usize) << 16)
        | (((v[2] & 0xff) as usize) << 8)
        | (v[3] & 0xff) as usize;
    let mut result = Vec::new();
    for i in 0..(len - 4) / MIXED_MATRIX_D_L {
        let mut tmp = vec![0; MIXED_MATRIX_T_L];
        mixed_reversible_matrix_core2(
            &mut tmp,
            &v[i * MIXED_MATRIX_D_L + 4..(i + 1) * MIXED_MATRIX_D_L + 4].to_vec(),
            &MIXED_MATRIX2,
        );
        result.append(&mut tmp);
    }
    v.clear();
    v.append(&mut result);
    v.truncate(actually_len);
}

fn mixed_movebit(v: &mut Vec<u8>) {
    for i in 0..v.len() {
        v[i] = (v[i] >> 4) ^ (v[i] << 4);
    }
}

fn mixed_movebit2_core(v: &mut Vec<u8>, oper: u8) {
    for i in 0..v.len() {
        if oper == 0x00 {
            v[i] = (v[i] >> 4 ^ 0x05) ^ (v[i] << 4);
        } else {
            v[i] = (v[i] >> 4) ^ (v[i] << 4 ^ 80);
        }
    }
}

fn mixed_movebit2(v: &mut Vec<u8>) {
    mixed_movebit2_core(v, 0);
}

fn mixed_reverse_movebit2(v: &mut Vec<u8>) {
    mixed_movebit2_core(v, 1);
}

fn mixed_movebit3(v: &mut Vec<u8>) {
    for i in 0..v.len() {
        let t1 = (v[i] << (2 - 1)) >> 7;
        let t2 = (v[i] << (3 - 1)) >> 7;
        let t3 = (v[i] << (6 - 1)) >> 7;
        let t4 = (v[i] << (7 - 1)) >> 7;

        if t1 == 0 && t3 == 1 {
            v[i] = v[i] + (1 << (8 - 2)) - (1 << (8 - 6));
        }
        if t1 == 1 && t3 == 0 {
            v[i] = v[i] - (1 << (8 - 2)) + (1 << (8 - 6));
        }
        if t2 == 0 && t4 == 1 {
            v[i] = v[i] + (1 << (8 - 3)) - (1 << (8 - 7));
        }
        if t2 == 1 && t4 == 0 {
            v[i] = v[i] - (1 << (8 - 3)) + (1 << (8 - 7));
        }
    }
}

fn mixed_movebit4(v: &mut Vec<u8>) {
    for i in 0..v.len() {
        v[i] = !v[i];
    }
}

fn mixed_bitmove(v: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();
    let movebit: u8 = rng.gen_range(1..8);
    v.insert(0, movebit);
    let len = v.len();
    let mut temp: u8 = 0;
    let mut suffix_bit: u8 = 0;
    for i in 1..len {
        temp = v[i];
        v[i] = suffix_bit | (temp >> (8 - movebit));
        suffix_bit = temp << movebit;
    }
    v.insert(len, suffix_bit);
}

fn mixed_bitmove_reverse(v: &mut Vec<u8>) {
    let movebit: u8 = v[0];
    let mut temp: u8 = 0;
    let mut suffix_bit = v[1] << (8 - movebit);
    let len = v.len();
    for i in 0..len - 2 {
        temp = v[i + 2];
        v[i] = suffix_bit | (temp >> movebit);
        suffix_bit = temp << (8 - movebit);
    }

    v.truncate(len - 2);
}

fn mixed_bitmove_cycle(v: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();
    let movebit: u8 = rng.gen_range(1..8);
    v.insert(0, movebit);
    let mut temp: u8 = 0;
    for i in 1..v.len() {
        temp = v[i];
        v[i] = (temp << movebit) | (temp >> (8 - movebit));
    }
}

fn mixed_bitmove_cycle_reverse(v: &mut Vec<u8>) {
    let movebit: u8 = v[0];
    let mut temp: u8 = 0;
    for i in 1..v.len() {
        temp = v[i];
        v[i - 1] = (temp >> movebit) | (temp << (8 - movebit));
    }

    v.truncate(v.len() - 1);
}

// 所有加密模式关联编号
pub fn model_encrypt(v: &mut Vec<u8>, model: u32) {
    match model {
        0 => mixed_switchmodel(v),
        1 => mixed_matrix_t_refra(v),
        2 => mixed_matrix_t_refra_re(v),
        3 => mixed_matrix_t_row(v),
        4 => mixed_matrix_t_col(v),
        5 => mixed_matrix_f_refra(v),
        6 => mixed_matrix_f_refra_re(v),
        7 => mixed_matrix_f_row(v),
        8 => mixed_matrix_f_col(v),
        9 => mixed_xor(v),
        10 => mixed_netfestival(v),
        11 => mixed_movebit(v),
        12 => mixed_movebit2(v),
        13 => mixed_movebit3(v),
        14 => mixed_movebit4(v),
        15 => mixed_bitmove(v),
        16 => mixed_bitmove_cycle(v),
        _ => unimplemented!(),
    };
}

// 所有加密模式关联编号
pub fn model_decrypt(v: &mut Vec<u8>, model: u32) {
    match model {
        0 => mixed_switchmodel(v),
        1 => mixed_reverse_matrix_t_refra(v),
        2 => mixed_reverse_matrix_t_refra_re(v),
        3 => mixed_reverse_matrix_t_row(v),
        4 => mixed_reverse_matrix_t_col(v),
        5 => mixed_reverse_matrix_f_refra(v),
        6 => mixed_reverse_matrix_f_refra_re(v),
        7 => mixed_reverse_matrix_f_row(v),
        8 => mixed_reverse_matrix_f_col(v),
        9 => mixed_xor(v),
        10 => mixed_netfestival(v),
        11 => mixed_movebit(v),
        12 => mixed_reverse_movebit2(v),
        13 => mixed_movebit3(v),
        14 => mixed_movebit4(v),
        15 => mixed_bitmove_reverse(v),
        16 => mixed_bitmove_cycle_reverse(v),
        _ => unimplemented!(),
    };
}

// 返回目前有多少模式
pub fn model_count() -> u32 {
    17
}

pub fn model_rand_choice() -> u32 {
    let mut rng = rand::thread_rng();
    let result: u32 = rng.gen_range(0..model_count());
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn encrypt_and_decrypt() {
        let mut v: Vec<u8> = vec![
            25, 52, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 1, 1, 1, 3, 5, 3, 5, 67, 2, 43,
        ];
        let vc = v.clone();
        for i in 0..model_count() {
            println!("{}", i);
            model_encrypt(&mut v, i);
            model_decrypt(&mut v, i);
            assert_eq!(vc, v);
        }
    }
}
